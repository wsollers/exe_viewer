#include <peelf/gdb_remote.hpp>

#include "model/binary_model.hpp"

#include <peelf/capability_matrix.hpp>
#include <peelf/debugger.hpp>
#include <peelf/execution_timeline.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <format>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace peelf {
namespace {

[[nodiscard]] std::string hex_encode_bytes(std::span<const std::uint8_t> bytes) {
    static constexpr std::string_view kHex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2u);
    for (const std::uint8_t b : bytes) {
        out.push_back(kHex[static_cast<std::size_t>((b >> 4u) & 0xFu)]);
        out.push_back(kHex[static_cast<std::size_t>(b & 0xFu)]);
    }
    return out;
}

[[nodiscard]] std::vector<std::uint8_t> hex_decode_bytes(std::string_view hex) {
    auto nibble = [](char ch) noexcept -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return 10 + (ch - 'a');
        if (ch >= 'A' && ch <= 'F') return 10 + (ch - 'A');
        return -1;
    };
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2u);
    for (std::size_t i = 0u; i + 1u < hex.size(); i += 2u) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1u]);
        if (hi < 0 || lo < 0) {
            break;
        }
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

[[nodiscard]] std::string encode_reg_hex(
    std::uint64_t val,
    std::size_t byte_len,
    Endianness endian) {
    std::vector<std::uint8_t> buf(byte_len, 0u);
    if (endian == Endianness::Little) {
        for (std::size_t i = 0u; i < byte_len && i < 8u; ++i) {
            buf[i] = static_cast<std::uint8_t>((val >> (i * 8u)) & 0xFFu);
        }
    } else {
        for (std::size_t i = 0u; i < byte_len && i < 8u; ++i) {
            buf[byte_len - 1u - i] = static_cast<std::uint8_t>((val >> (i * 8u)) & 0xFFu);
        }
    }
    return hex_encode_bytes(buf);
}

[[nodiscard]] std::uint64_t decode_reg_hex(std::string_view hex, Endianness endian) {
    const std::vector<std::uint8_t> bytes = hex_decode_bytes(hex);
    std::uint64_t val = 0u;
    if (endian == Endianness::Little) {
        const std::size_t n = std::min<std::size_t>(bytes.size(), 8u);
        for (std::size_t i = 0u; i < n; ++i) {
            val |= static_cast<std::uint64_t>(bytes[i]) << (i * 8u);
        }
    } else {
        const std::size_t n = std::min<std::size_t>(bytes.size(), 8u);
        for (std::size_t i = 0u; i < n; ++i) {
            val = (val << 8u) | static_cast<std::uint64_t>(bytes[bytes.size() - n + i]);
        }
    }
    return val;
}

struct StubRegSpec {
    std::uint32_t regnum{0};
    std::size_t byte_size{8};
    std::uint64_t value{0};
};

struct ArmedStubBp {
    std::uint8_t type{0};
    std::uint64_t addr{0};
    std::uint32_t kind{0};
};

class FakeDebugStubState {
public:
    mutable std::mutex mutex{};
    std::condition_variable cv{};

    bool open{true};
    bool no_ack_mode{false};
    Endianness endian{Endianness::Little};
    std::uint32_t pc_regnum{0};

    std::string qsupported_reply{
        "PacketSize=1000;QStartNoAckMode+;multiprocess+;vContSupported+;"
        "qXfer:features:read+;qXfer:memory-map:read+"};
    std::string vcont_reply{"vCont;c;C;s;S;t"};
    std::string halt_reply{"T05thread:p10.20;"};
    std::string active_thread{"p10.20"};
    std::string target_xml{};
    std::optional<std::string> memory_map_xml{};

    std::vector<StubRegSpec> regs{};
    std::map<std::uint64_t, std::vector<std::uint8_t>> memory{};
    std::vector<ArmedStubBp> armed_bps{};

    bool z0_unsupported{false};
    bool hw_bp_unsupported{false};
    bool p_write_unsupported{false};
    bool fail_z0_disarm{false};
    bool fail_detach{false};
    bool hold_running_until_interrupt{false};
    bool waiting_for_interrupt{false};

    std::size_t interrupt_count{0};
    std::vector<std::string> received_commands{};
    std::function<std::optional<std::string>(FakeDebugStubState&, std::string_view)> on_resume{};

    std::deque<std::uint8_t> tx_to_client{};
    std::string rx_from_client{};
    std::size_t thread_page_idx{0};

    void set_reg(std::uint32_t regnum, std::uint64_t val) {
        for (StubRegSpec& r : regs) {
            if (r.regnum == regnum) {
                r.value = val;
                return;
            }
        }
    }

    [[nodiscard]] std::uint64_t get_reg(std::uint32_t regnum) const {
        for (const StubRegSpec& r : regs) {
            if (r.regnum == regnum) {
                return r.value;
            }
        }
        return 0u;
    }

    void write_mem(std::uint64_t addr, std::span<const std::uint8_t> data) {
        for (auto& [base, seg] : memory) {
            if (addr >= base && addr + data.size() <= base + seg.size()) {
                std::copy(data.begin(),
                          data.end(),
                          seg.begin() + static_cast<std::ptrdiff_t>(addr - base));
                return;
            }
        }
        memory[addr] = std::vector<std::uint8_t>(data.begin(), data.end());
    }

    [[nodiscard]] std::optional<std::vector<std::uint8_t>> read_mem(
        std::uint64_t addr,
        std::size_t len) const {
        std::vector<std::uint8_t> out(len, 0u);
        for (std::size_t i = 0u; i < len; ++i) {
            const std::uint64_t cur = addr + i;
            bool found = false;
            for (const auto& [base, seg] : memory) {
                if (cur >= base && cur < base + seg.size()) {
                    out[i] = seg[static_cast<std::size_t>(cur - base)];
                    found = true;
                    break;
                }
            }
            if (!found) {
                return std::nullopt;
            }
        }
        return out;
    }

    [[nodiscard]] bool has_armed_bp(std::uint8_t type, std::uint64_t addr) const noexcept {
        return std::ranges::any_of(armed_bps, [&](const ArmedStubBp& bp) {
            return bp.type == type && bp.addr == addr;
        });
    }

    void enqueue_raw_locked(std::string_view raw) {
        for (const char ch : raw) {
            tx_to_client.push_back(static_cast<std::uint8_t>(ch));
        }
        cv.notify_all();
    }

    void enqueue_frame_locked(std::string_view payload) {
        enqueue_raw_locked(rsp_encode_frame(payload));
    }

    [[nodiscard]] std::string encode_g_locked() const {
        std::string out;
        for (const StubRegSpec& r : regs) {
            out += encode_reg_hex(r.value, r.byte_size, endian);
        }
        return out;
    }

    [[nodiscard]] std::string handle_qxfer_slice_locked(
        std::string_view content,
        std::string_view off_len) const {
        const std::size_t comma = off_len.find(',');
        if (comma == std::string_view::npos) {
            return "E01";
        }
        const auto off = static_cast<std::size_t>(
            std::stoull(std::string(off_len.substr(0, comma)), nullptr, 16));
        const auto len = static_cast<std::size_t>(
            std::stoull(std::string(off_len.substr(comma + 1u)), nullptr, 16));
        if (off >= content.size()) {
            return "l";
        }
        const std::size_t take = std::min(content.size() - off, len);
        std::string out(1u, (off + take >= content.size()) ? 'l' : 'm');
        out.append(content.substr(off, take));
        return out;
    }

    void process_client_bytes(std::span<const std::uint8_t> data) {
        std::scoped_lock lock(mutex);
        for (const std::uint8_t byte : data) {
            rx_from_client.push_back(static_cast<char>(byte));
        }

        while (!rx_from_client.empty()) {
            const char lead = rx_from_client.front();
            if (lead == '+' || lead == '-') {
                rx_from_client.erase(0, 1);
                continue;
            }
            if (static_cast<std::uint8_t>(lead) == 0x03u) {
                rx_from_client.erase(0, 1);
                ++interrupt_count;
                if (waiting_for_interrupt) {
                    waiting_for_interrupt = false;
                    halt_reply = std::format("T02thread:{};", active_thread);
                    enqueue_frame_locked(halt_reply);
                }
                continue;
            }
            const std::size_t dollar = rx_from_client.find('$');
            if (dollar == std::string::npos) {
                rx_from_client.clear();
                break;
            }
            if (dollar > 0u) {
                rx_from_client.erase(0, dollar);
            }
            const std::size_t hash = rx_from_client.find('#', 1u);
            if (hash == std::string::npos || hash + 2u >= rx_from_client.size()) {
                break;
            }
            const std::string frame = rx_from_client.substr(0, hash + 3u);
            rx_from_client.erase(0, hash + 3u);

            const std::string_view wire = std::string_view(frame).substr(1u, hash - 1u);
            const std::string_view csum_hex = std::string_view(frame).substr(hash + 1u, 2u);
            const std::vector<std::uint8_t> csum_bytes = hex_decode_bytes(csum_hex);
            if (csum_bytes.size() != 1u || csum_bytes[0] != compute_rsp_checksum(wire)) {
                enqueue_raw_locked("-");
                continue;
            }
            auto decoded = rsp_decode_wire_payload(wire);
            if (!decoded) {
                enqueue_raw_locked("-");
                continue;
            }
            if (!no_ack_mode) {
                enqueue_raw_locked("+");
            }

            const std::string& cmd = *decoded;
            received_commands.push_back(cmd);

            if (cmd == "QStartNoAckMode") {
                enqueue_frame_locked("OK");
                no_ack_mode = true;
                continue;
            }

            const bool is_resume =
                (cmd.starts_with("vCont;") && cmd != "vCont?") ||
                cmd == "c" || cmd.starts_with("C") ||
                cmd == "s" || cmd.starts_with("S");
            if (is_resume && hold_running_until_interrupt &&
                (cmd.starts_with("vCont;c") || cmd.starts_with("vCont;C") ||
                 cmd == "c" || cmd.starts_with("C"))) {
                waiting_for_interrupt = true;
                continue;
            }

            const std::string reply = dispatch_command_locked(cmd);
            enqueue_frame_locked(reply);
        }
    }

    [[nodiscard]] std::string dispatch_command_locked(std::string_view cmd) {
        if (cmd.starts_with("qSupported")) {
            return qsupported_reply;
        }
        if (cmd == "vCont?") {
            return vcont_reply;
        }
        if (cmd == "?") {
            return halt_reply;
        }
        if (cmd.starts_with("qXfer:features:read:target.xml:")) {
            if (target_xml.empty()) {
                return "";
            }
            return handle_qxfer_slice_locked(
                target_xml,
                cmd.substr(std::string_view{"qXfer:features:read:target.xml:"}.size()));
        }
        if (cmd.starts_with("qXfer:memory-map:read::")) {
            if (!memory_map_xml.has_value()) {
                return "";
            }
            return handle_qxfer_slice_locked(
                *memory_map_xml,
                cmd.substr(std::string_view{"qXfer:memory-map:read::"}.size()));
        }
        if (cmd.starts_with("qXfer:")) {
            return "";
        }
        if (cmd == "qfThreadInfo") {
            thread_page_idx = 1u;
            return "m" + active_thread;
        }
        if (cmd == "qsThreadInfo") {
            return "l";
        }
        if (cmd == "qC") {
            return "QC" + active_thread;
        }
        if (cmd.starts_with("Hg") || cmd.starts_with("Hc")) {
            return "OK";
        }
        if (cmd == "g") {
            return encode_g_locked();
        }
        if (cmd.starts_with("G")) {
            std::string_view hex = cmd.substr(1u);
            std::size_t cursor = 0u;
            for (StubRegSpec& r : regs) {
                const std::size_t need = r.byte_size * 2u;
                if (cursor + need > hex.size()) {
                    return "E01";
                }
                r.value = decode_reg_hex(hex.substr(cursor, need), endian);
                cursor += need;
            }
            return "OK";
        }
        if (cmd.starts_with("p")) {
            const auto regnum = static_cast<std::uint32_t>(
                std::stoul(std::string(cmd.substr(1u)), nullptr, 16));
            for (const StubRegSpec& r : regs) {
                if (r.regnum == regnum) {
                    return encode_reg_hex(r.value, r.byte_size, endian);
                }
            }
            return "E01";
        }
        if (cmd.starts_with("P")) {
            if (p_write_unsupported) {
                return "";
            }
            const std::size_t eq = cmd.find('=');
            if (eq == std::string_view::npos) {
                return "E01";
            }
            const auto regnum = static_cast<std::uint32_t>(
                std::stoul(std::string(cmd.substr(1u, eq - 1u)), nullptr, 16));
            const std::string_view val_hex = cmd.substr(eq + 1u);
            for (StubRegSpec& r : regs) {
                if (r.regnum == regnum) {
                    if (val_hex.size() != r.byte_size * 2u) {
                        return "E02";
                    }
                    r.value = decode_reg_hex(val_hex, endian);
                    return "OK";
                }
            }
            return "E01";
        }
        if (cmd.starts_with("m")) {
            const std::size_t comma = cmd.find(',');
            if (comma == std::string_view::npos) {
                return "E01";
            }
            const auto addr = std::stoull(std::string(cmd.substr(1u, comma - 1u)), nullptr, 16);
            const auto len = static_cast<std::size_t>(
                std::stoull(std::string(cmd.substr(comma + 1u)), nullptr, 16));
            const auto bytes = read_mem(addr, len);
            if (!bytes.has_value()) {
                return "E14";
            }
            return hex_encode_bytes(*bytes);
        }
        if (cmd.starts_with("M")) {
            const std::size_t comma = cmd.find(',');
            const std::size_t colon = cmd.find(':');
            if (comma == std::string_view::npos || colon == std::string_view::npos || colon < comma) {
                return "E01";
            }
            const auto addr = std::stoull(std::string(cmd.substr(1u, comma - 1u)), nullptr, 16);
            const auto len = static_cast<std::size_t>(
                std::stoull(std::string(cmd.substr(comma + 1u, colon - comma - 1u)), nullptr, 16));
            const std::vector<std::uint8_t> bytes = hex_decode_bytes(cmd.substr(colon + 1u));
            if (bytes.size() != len) {
                return "E02";
            }
            write_mem(addr, bytes);
            return "OK";
        }
        if ((cmd.starts_with("Z") || cmd.starts_with("z")) && cmd.size() >= 4u && cmd[2] == ',') {
            const bool arm = cmd[0] == 'Z';
            const auto type = static_cast<std::uint8_t>(cmd[1] - '0');
            if (type == 0u && z0_unsupported) {
                return "";
            }
            if (type >= 1u && hw_bp_unsupported) {
                return "";
            }
            if (!arm && type == 0u && fail_z0_disarm) {
                return "E01";
            }
            const std::string_view rest = cmd.substr(3u);
            const std::size_t comma = rest.find(',');
            if (comma == std::string_view::npos) {
                return "E01";
            }
            const auto addr = std::stoull(std::string(rest.substr(0, comma)), nullptr, 16);
            const auto kind = static_cast<std::uint32_t>(
                std::stoul(std::string(rest.substr(comma + 1u)), nullptr, 16));
            if (arm) {
                if (!has_armed_bp(type, addr)) {
                    armed_bps.push_back(ArmedStubBp{.type = type, .addr = addr, .kind = kind});
                }
            } else {
                std::erase_if(armed_bps, [&](const ArmedStubBp& bp) {
                    return bp.type == type && bp.addr == addr;
                });
            }
            return "OK";
        }
        if (cmd == "D") {
            if (fail_detach) {
                return "E05";
            }
            return "OK";
        }
        if (cmd == "k") {
            open = false;
            return "OK";
        }
        if (cmd.starts_with("vCont;") || cmd == "c" || cmd.starts_with("C") ||
            cmd == "s" || cmd.starts_with("S")) {
            if (on_resume) {
                if (auto custom = on_resume(*this, cmd); custom.has_value()) {
                    halt_reply = *custom;
                    return *custom;
                }
            }
            // Default step advances PC by 4 (or 1 on x86_64 nop) and returns SIGTRAP stop.
            const std::uint64_t cur_pc = get_reg(pc_regnum);
            set_reg(pc_regnum, cur_pc + 4u);
            halt_reply = std::format("T05thread:{};", active_thread);
            return halt_reply;
        }
        return "";
    }
};

class FakeDebugRspTransport final : public IRspTransport {
public:
    explicit FakeDebugRspTransport(std::shared_ptr<FakeDebugStubState> state) noexcept
        : state_(std::move(state)) {}

    [[nodiscard]] Result<void> write_all(
        std::span<const std::uint8_t> data,
        std::chrono::milliseconds /*timeout*/,
        std::stop_token /*stop_token*/ = {}) override {
        if (!state_) {
            return make_error("null stub state");
        }
        {
            std::scoped_lock lock(state_->mutex);
            if (!state_->open) {
                return make_error("stub closed");
            }
        }
        state_->process_client_bytes(data);
        return {};
    }

    [[nodiscard]] Result<RspReadOutcome> read_some(
        std::span<std::uint8_t> buffer,
        std::chrono::milliseconds timeout,
        std::stop_token stop_token = {}) override {
        if (stop_token.stop_requested()) {
            return RspReadOutcome{.status = RspIoStatus::Cancelled, .bytes_read = 0u};
        }
        if (!state_) {
            return make_error("null stub state");
        }
        if (buffer.empty()) {
            return RspReadOutcome{.status = RspIoStatus::Ok, .bytes_read = 0u};
        }
        std::unique_lock lock(state_->mutex);
        if (state_->tx_to_client.empty() && timeout.count() > 0) {
            state_->cv.wait_for(lock, timeout, [&] {
                return !state_->tx_to_client.empty() || !state_->open ||
                       stop_token.stop_requested();
            });
        }
        if (stop_token.stop_requested()) {
            return RspReadOutcome{.status = RspIoStatus::Cancelled, .bytes_read = 0u};
        }
        if (state_->tx_to_client.empty()) {
            if (!state_->open) {
                return RspReadOutcome{.status = RspIoStatus::EndOfStream, .bytes_read = 0u};
            }
            return RspReadOutcome{.status = RspIoStatus::Timeout, .bytes_read = 0u};
        }
        const std::size_t take = std::min(buffer.size(), state_->tx_to_client.size());
        for (std::size_t i = 0u; i < take; ++i) {
            buffer[i] = state_->tx_to_client.front();
            state_->tx_to_client.pop_front();
        }
        return RspReadOutcome{.status = RspIoStatus::Ok, .bytes_read = take};
    }

    void close() noexcept override {
        if (state_) {
            std::scoped_lock lock(state_->mutex);
            state_->open = false;
            state_->cv.notify_all();
        }
    }

    [[nodiscard]] bool is_open() const noexcept override {
        if (!state_) {
            return false;
        }
        std::scoped_lock lock(state_->mutex);
        return state_->open;
    }

    [[nodiscard]] std::string endpoint_description() const override {
        return "fake-rsp://127.0.0.1:1234";
    }

private:
    std::shared_ptr<FakeDebugStubState> state_;
};

[[nodiscard]] std::shared_ptr<FakeDebugStubState> make_x86_64_stub() {
    auto s = std::make_shared<FakeDebugStubState>();
    s->endian = Endianness::Little;
    s->pc_regnum = 3u;
    s->target_xml =
        "<target version=\"1.0\">"
        "<architecture>i386:x86-64</architecture>"
        "<osabi>GNU/Linux</osabi>"
        "<feature name=\"org.gnu.gdb.i386.core\">"
        "<reg name=\"rax\" bitsize=\"64\" regnum=\"0\"/>"
        "<reg name=\"rbx\" bitsize=\"64\" regnum=\"1\"/>"
        "<reg name=\"rsp\" bitsize=\"64\" regnum=\"2\" type=\"data_ptr\"/>"
        "<reg name=\"rip\" bitsize=\"64\" regnum=\"3\" type=\"code_ptr\"/>"
        "<reg name=\"eflags\" bitsize=\"32\" regnum=\"4\"/>"
        "</feature>"
        "</target>";
    s->memory_map_xml =
        "<memory-map>"
        "<memory type=\"ram\" start=\"0x400000\" length=\"0x4000\"/>"
        "<memory type=\"ram\" start=\"0x7ffffffde000\" length=\"0x4000\"/>"
        "</memory-map>";
    s->regs = {
        StubRegSpec{.regnum = 0u, .byte_size = 8u, .value = 0x1111u},
        StubRegSpec{.regnum = 1u, .byte_size = 8u, .value = 0x2222u},
        StubRegSpec{.regnum = 2u, .byte_size = 8u, .value = 0x7fffffffe000ULL},
        StubRegSpec{.regnum = 3u, .byte_size = 8u, .value = 0x401000ULL},
        StubRegSpec{.regnum = 4u, .byte_size = 4u, .value = 0x202u},
    };
    s->memory[0x400000ULL] = std::vector<std::uint8_t>(0x4000u, 0x90u);
    s->memory[0x7ffffffde000ULL] = std::vector<std::uint8_t>(0x4000u, 0x00u);
    return s;
}

[[nodiscard]] std::shared_ptr<FakeDebugStubState> make_aarch64_stub() {
    auto s = std::make_shared<FakeDebugStubState>();
    s->endian = Endianness::Little;
    s->pc_regnum = 3u;
    s->target_xml =
        "<target version=\"1.0\">"
        "<architecture>aarch64</architecture>"
        "<osabi>GNU/Linux</osabi>"
        "<feature name=\"org.gnu.gdb.aarch64.core\">"
        "<reg name=\"x0\" bitsize=\"64\" regnum=\"0\"/>"
        "<reg name=\"x30\" bitsize=\"64\" regnum=\"1\" type=\"code_ptr\"/>"
        "<reg name=\"sp\" bitsize=\"64\" regnum=\"2\" type=\"data_ptr\"/>"
        "<reg name=\"pc\" bitsize=\"64\" regnum=\"3\" type=\"code_ptr\"/>"
        "<reg name=\"cpsr\" bitsize=\"32\" regnum=\"4\"/>"
        "</feature>"
        "</target>";
    s->memory_map_xml =
        "<memory-map>"
        "<memory type=\"ram\" start=\"0x400000\" length=\"0x8000\"/>"
        "</memory-map>";
    s->regs = {
        StubRegSpec{.regnum = 0u, .byte_size = 8u, .value = 0xAAu},
        StubRegSpec{.regnum = 1u, .byte_size = 8u, .value = 0x400104ULL},
        StubRegSpec{.regnum = 2u, .byte_size = 8u, .value = 0x407000ULL},
        StubRegSpec{.regnum = 3u, .byte_size = 8u, .value = 0x400100ULL},
        StubRegSpec{.regnum = 4u, .byte_size = 4u, .value = 0x60000000u},
    };
    s->memory[0x400000ULL] = std::vector<std::uint8_t>(0x8000u, 0x00u);
    // `bl #0x100` (0x94000040 LE) at 0x400100; `nop` (0xD503201F LE) at 0x400104.
    const std::array<std::uint8_t, 8> code{
        0x40, 0x00, 0x00, 0x94,
        0x1F, 0x20, 0x03, 0xD5,
    };
    s->write_mem(0x400100ULL, code);
    return s;
}

[[nodiscard]] std::shared_ptr<FakeDebugStubState> make_riscv64_stub() {
    auto s = std::make_shared<FakeDebugStubState>();
    s->endian = Endianness::Little;
    s->pc_regnum = 3u;
    s->target_xml =
        "<target version=\"1.0\">"
        "<architecture>riscv:rv64</architecture>"
        "<feature name=\"org.gnu.gdb.riscv.cpu\">"
        "<reg name=\"zero\" bitsize=\"64\" regnum=\"0\"/>"
        "<reg name=\"ra\" bitsize=\"64\" regnum=\"1\" type=\"code_ptr\"/>"
        "<reg name=\"sp\" bitsize=\"64\" regnum=\"2\" type=\"data_ptr\"/>"
        "<reg name=\"pc\" bitsize=\"64\" regnum=\"3\" type=\"code_ptr\"/>"
        "</feature>"
        "</target>";
    s->memory_map_xml =
        "<memory-map>"
        "<memory type=\"ram\" start=\"0x10000\" length=\"0x4000\"/>"
        "</memory-map>";
    s->regs = {
        StubRegSpec{.regnum = 0u, .byte_size = 8u, .value = 0u},
        StubRegSpec{.regnum = 1u, .byte_size = 8u, .value = 0x10004ULL},
        StubRegSpec{.regnum = 2u, .byte_size = 8u, .value = 0x13F00ULL},
        StubRegSpec{.regnum = 3u, .byte_size = 8u, .value = 0x10000ULL},
    };
    s->memory[0x10000ULL] = std::vector<std::uint8_t>(0x4000u, 0x13u);
    // `jal ra, +0x100` (0x100000ef LE) at 0x10000; `addi x0, x0, 0` (0x00000013 LE) at 0x10004.
    const std::array<std::uint8_t, 8> code{
        0xEF, 0x00, 0x00, 0x10,
        0x13, 0x00, 0x00, 0x00,
    };
    s->write_mem(0x10000ULL, code);
    return s;
}

[[nodiscard]] std::shared_ptr<FakeDebugStubState> make_ppc64_be_stub() {
    auto s = std::make_shared<FakeDebugStubState>();
    s->endian = Endianness::Big;
    s->pc_regnum = 2u;
    s->target_xml =
        "<target version=\"1.0\">"
        "<architecture>powerpc:common64</architecture>"
        "<osabi>GNU/Linux</osabi>"
        "<feature name=\"org.gnu.gdb.power.core\">"
        "<reg name=\"r0\" bitsize=\"64\" regnum=\"0\"/>"
        "<reg name=\"r1\" bitsize=\"64\" regnum=\"1\" type=\"data_ptr\"/>"
        "<reg name=\"pc\" bitsize=\"64\" regnum=\"2\" type=\"code_ptr\"/>"
        "<reg name=\"lr\" bitsize=\"64\" regnum=\"3\" type=\"code_ptr\"/>"
        "<reg name=\"cr\" bitsize=\"32\" regnum=\"4\"/>"
        "</feature>"
        "</target>";
    s->memory_map_xml =
        "<memory-map>"
        "<memory type=\"ram\" start=\"0x10000000\" length=\"0x4000\"/>"
        "</memory-map>";
    s->regs = {
        StubRegSpec{.regnum = 0u, .byte_size = 8u, .value = 0x123456789ABCDEF0ULL},
        StubRegSpec{.regnum = 1u, .byte_size = 8u, .value = 0x10003800ULL},
        StubRegSpec{.regnum = 2u, .byte_size = 8u, .value = 0x10000400ULL},
        StubRegSpec{.regnum = 3u, .byte_size = 8u, .value = 0x10000404ULL},
        StubRegSpec{.regnum = 4u, .byte_size = 4u, .value = 0x28000022u},
    };
    s->memory[0x10000000ULL] = std::vector<std::uint8_t>(0x4000u, 0x60u);
    // PowerPC64 BE `bl .+0x100` (0x48000101 BE) at 0x10000400; `nop` (`ori 0,0,0` = 0x60000000 BE) at 0x10000404.
    const std::array<std::uint8_t, 8> code{
        0x48, 0x00, 0x01, 0x01,
        0x60, 0x00, 0x00, 0x00,
    };
    s->write_mem(0x10000400ULL, code);
    return s;
}

TEST(GdbRemoteDebugTest, RejectsMissingExplicitDebugConsentWithoutSendingPackets) {
    auto stub = make_x86_64_stub();
    const ExplicitDebugConsent denied{.acknowledged_target_mutation = false};

    auto rejected = GdbRemoteBackend::open_debug(
        std::make_unique<FakeDebugRspTransport>(stub),
        denied);
    ASSERT_FALSE(rejected.has_value());
    EXPECT_NE(rejected.error().message.find("ExplicitDebugConsent"), std::string::npos);
    EXPECT_TRUE(stub->received_commands.empty());

    GdbRemoteOpenOptions opts{};
    opts.endpoint.host = "127.0.0.1";
    opts.endpoint.port = 1234;
    auto ep_rejected = GdbRemoteBackend::open_debug(opts, denied);
    ASSERT_FALSE(ep_rejected.has_value());
    EXPECT_NE(ep_rejected.error().message.find("ExplicitDebugConsent"), std::string::npos);

    auto spec_rejected = GdbRemoteBackend::open_debug("127.0.0.1:1234", denied, false);
    ASSERT_FALSE(spec_rejected.has_value());
    EXPECT_NE(spec_rejected.error().message.find("ExplicitDebugConsent"), std::string::npos);

    // Non-loopback plaintext endpoint without explicit opt-in is also rejected before connecting.
    auto unenc_rejected = GdbRemoteBackend::open_debug(
        "192.0.2.55:1234",
        ExplicitDebugConsent{.acknowledged_target_mutation = true},
        /*allow_unencrypted_remote_endpoint=*/false);
    ASSERT_FALSE(unenc_rejected.has_value());
}

TEST(GdbRemoteDebugTest, X86_64VContStepSoftwareBreakpointsStepOverStepOutAndMemoryWrite) {
    auto stub = make_x86_64_stub();
    // 0x401000: `call 0x402000` (E8 FB 0F 00 00, 5 bytes -> fallthrough 0x401005)
    // 0x401005: `nop` (90)
    // 0x402000: `ret` (C3)
    const std::array<std::uint8_t, 6> call_site{0xE8, 0xFB, 0x0F, 0x00, 0x00, 0x90};
    stub->write_mem(0x401000ULL, call_site);
    const std::array<std::uint8_t, 1> callee_ret{0xC3};
    stub->write_mem(0x402000ULL, callee_ret);

    stub->on_resume = [](FakeDebugStubState& s, std::string_view cmd) -> std::optional<std::string> {
        const std::uint64_t rip = s.get_reg(3u);
        if (cmd.starts_with("vCont;s")) {
            s.set_reg(3u, rip + 1u);
            return std::format("T0503:{};thread:{};",
                               encode_reg_hex(rip + 1u, 8u, Endianness::Little),
                               s.active_thread);
        }
        // `vCont;c`: simulate hitting any armed Z0 software breakpoint.
        for (const ArmedStubBp& bp : s.armed_bps) {
            if (bp.type == 0u) {
                s.set_reg(3u, bp.addr);
                return std::format("T05swbreak:;03:{};thread:{};",
                                   encode_reg_hex(bp.addr, 8u, Endianness::Little),
                                   s.active_thread);
            }
        }
        return std::nullopt;
    };

    auto opened = GdbRemoteBackend::open_debug(
        std::make_unique<FakeDebugRspTransport>(stub),
        ExplicitDebugConsent{.acknowledged_target_mutation = true});
    ASSERT_TRUE(opened.has_value()) << opened.error().message;
    auto& dbg = **opened;
    auto* gdb_dbg = dynamic_cast<IGdbRemoteDebugSession*>(&dbg);
    ASSERT_NE(gdb_dbg, nullptr);

    EXPECT_TRUE(gdb_dbg->vcont_capabilities().supported);
    EXPECT_TRUE(gdb_dbg->vcont_capabilities().cont);
    EXPECT_TRUE(gdb_dbg->vcont_capabilities().step);
    EXPECT_FALSE(dbg.session().is_read_only());
    EXPECT_EQ(dbg.state(), debugger::DebugSessionState::Paused);
    const ThreadId tid = dbg.stop_status().active_tid;
    ASSERT_NE(tid, 0u);

    // Software breakpoint Z0/z0 lifecycle.
    auto bp = dbg.add_software_breakpoint(0x401080ULL, "target_fn");
    ASSERT_TRUE(bp.has_value()) << bp.error().message;
    EXPECT_TRUE(stub->has_armed_bp(0u, 0x401080ULL));

    ASSERT_TRUE(dbg.continue_execution(false).has_value());
    auto hit_stop = dbg.wait_for_stop(std::chrono::milliseconds{500});
    ASSERT_TRUE(hit_stop.has_value()) << hit_stop.error().message;
    ASSERT_TRUE(hit_stop->last_event.has_value());
    EXPECT_EQ(hit_stop->last_event->kind, debugger::DebugEventKind::BreakpointHit);
    EXPECT_EQ(hit_stop->last_event->address, 0x401080ULL);
    EXPECT_EQ(dbg.breakpoints().size(), 1u);
    EXPECT_EQ(dbg.breakpoints()[0].hit_count, 1u);

    ASSERT_TRUE(dbg.remove_breakpoint(bp->id).has_value());
    EXPECT_FALSE(stub->has_armed_bp(0u, 0x401080ULL));

    // Step over 5-byte x86_64 `call` at 0x401000 plants temporary Z0 at 0x401005 and cleans it up.
    ASSERT_TRUE(dbg.write_register(tid, "rip", 0x401000ULL).has_value());
    ASSERT_TRUE(dbg.step_over(tid).has_value());
    auto over_stop = dbg.wait_for_stop(std::chrono::milliseconds{500});
    ASSERT_TRUE(over_stop.has_value()) << over_stop.error().message;
    ASSERT_TRUE(over_stop->last_event.has_value());
    EXPECT_EQ(over_stop->last_event->kind, debugger::DebugEventKind::SingleStepCompleted);
    EXPECT_EQ(over_stop->instruction_pointer, 0x401005ULL);
    EXPECT_TRUE(dbg.breakpoints().empty());
    EXPECT_TRUE(stub->armed_bps.empty());

    // Step out from callee 0x402000 reads `[rsp]` return address (0x401005) and runs to it.
    const std::array<std::uint8_t, 8> ret_addr_le{
        0x05, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00};
    stub->write_mem(0x7fffffffe000ULL, ret_addr_le);
    ASSERT_TRUE(dbg.write_register(tid, "rip", 0x402000ULL).has_value());
    ASSERT_TRUE(dbg.step_out(tid).has_value());
    auto out_stop = dbg.wait_for_stop(std::chrono::milliseconds{500});
    ASSERT_TRUE(out_stop.has_value()) << out_stop.error().message;
    ASSERT_TRUE(out_stop->last_event.has_value());
    EXPECT_EQ(out_stop->last_event->kind, debugger::DebugEventKind::SingleStepCompleted);
    EXPECT_EQ(out_stop->instruction_pointer, 0x401005ULL);
    EXPECT_TRUE(stub->armed_bps.empty());

    // Step into uses `vCont;s:p10.20`.
    ASSERT_TRUE(dbg.step_into(tid).has_value());
    auto into_stop = dbg.wait_for_stop(std::chrono::milliseconds{500});
    ASSERT_TRUE(into_stop.has_value()) << into_stop.error().message;
    ASSERT_TRUE(into_stop->last_event.has_value());
    EXPECT_EQ(into_stop->last_event->kind, debugger::DebugEventKind::SingleStepCompleted);
    EXPECT_EQ(into_stop->instruction_pointer, 0x401006ULL);

    // `M` memory write works in IDebugSession::session() and is visible via shadowed memory reads.
    const std::array<std::uint8_t, 4> patch{0xDE, 0xAD, 0xBE, 0xEF};
    ASSERT_TRUE(dbg.session().write_memory(0x401200ULL, patch).has_value());
    std::array<std::uint8_t, 4> read_back{};
    auto got = dbg.session().read_memory(0x401200ULL, read_back);
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, 4u);
    EXPECT_EQ(read_back, patch);

    ASSERT_TRUE(dbg.detach().has_value());
    EXPECT_EQ(dbg.state(), debugger::DebugSessionState::Detached);
}

TEST(GdbRemoteDebugTest, AArch64WatchpointStopEmptyReplyDegradationStepOverAndStepOut) {
    auto stub = make_aarch64_stub();
    stub->on_resume = [](FakeDebugStubState& s, std::string_view /*cmd*/) -> std::optional<std::string> {
        for (const ArmedStubBp& bp : s.armed_bps) {
            if (bp.type == 2u) {
                s.set_reg(3u, 0x400120ULL);
                return std::format("T05watch:{:x};thread:{};", bp.addr, s.active_thread);
            }
            if (bp.type == 3u) {
                s.set_reg(3u, 0x400124ULL);
                return std::format("T05rwatch:{:x};thread:{};", bp.addr, s.active_thread);
            }
            if (bp.type == 0u) {
                s.set_reg(3u, bp.addr);
                return std::format("T05swbreak:;thread:{};", s.active_thread);
            }
        }
        return std::nullopt;
    };

    auto opened = GdbRemoteBackend::open_debug(
        std::make_unique<FakeDebugRspTransport>(stub),
        ExplicitDebugConsent{.acknowledged_target_mutation = true});
    ASSERT_TRUE(opened.has_value()) << opened.error().message;
    auto& dbg = **opened;
    auto* gdb_dbg = dynamic_cast<IGdbRemoteDebugSession*>(&dbg);
    ASSERT_NE(gdb_dbg, nullptr);
    const ThreadId tid = dbg.stop_status().active_tid;
    ASSERT_NE(tid, 0u);

    // Arm Z2 write watchpoint at 0x404000 and verify T05watch:404000; stop event + confirmed capability.
    auto wp = dbg.add_hardware_breakpoint(
        0x404000ULL,
        debugger::BreakpointKind::HardwareWrite,
        8u,
        "watched_global");
    ASSERT_TRUE(wp.has_value()) << wp.status.detail;
    EXPECT_TRUE(stub->has_armed_bp(2u, 0x404000ULL));
    EXPECT_EQ(gdb_dbg->capability_matrix().get(Operation::HardwareWatchpoints).state,
              SupportState::SupportedValidated);

    ASSERT_TRUE(dbg.continue_execution(false).has_value());
    auto wp_stop = dbg.wait_for_stop(std::chrono::milliseconds{500});
    ASSERT_TRUE(wp_stop.has_value()) << wp_stop.error().message;
    ASSERT_TRUE(wp_stop->last_event.has_value());
    EXPECT_EQ(wp_stop->last_event->kind, debugger::DebugEventKind::BreakpointHit);
    EXPECT_EQ(wp_stop->last_event->breakpoint_id, wp.value->id);
    EXPECT_EQ(wp_stop->last_event->address, 0x404000ULL);
    EXPECT_EQ(dbg.breakpoints()[0].hit_count, 1u);

    ASSERT_TRUE(dbg.remove_breakpoint(wp.value->id).has_value());

    // Arm Z3 read watchpoint at 0x404008 and verify T05rwatch:404008; stop event.
    auto rwp = gdb_dbg->add_read_watchpoint(0x404008ULL, 4u, "read_watched");
    ASSERT_TRUE(rwp.has_value()) << rwp.status.detail;
    EXPECT_TRUE(stub->has_armed_bp(3u, 0x404008ULL));
    ASSERT_TRUE(dbg.continue_execution(false).has_value());
    auto rwp_stop = dbg.wait_for_stop(std::chrono::milliseconds{500});
    ASSERT_TRUE(rwp_stop.has_value()) << rwp_stop.error().message;
    ASSERT_TRUE(rwp_stop->last_event.has_value());
    EXPECT_EQ(rwp_stop->last_event->kind, debugger::DebugEventKind::BreakpointHit);
    EXPECT_EQ(rwp_stop->last_event->address, 0x404008ULL);
    ASSERT_TRUE(dbg.remove_breakpoint(rwp.value->id).has_value());

    // Step over AArch64 `bl #0x100` at 0x400100 -> temporary Z0 at 0x400104.
    ASSERT_TRUE(dbg.write_register(tid, "pc", 0x400100ULL).has_value());
    ASSERT_TRUE(dbg.step_over(tid).has_value());
    auto over_stop = dbg.wait_for_stop(std::chrono::milliseconds{500});
    ASSERT_TRUE(over_stop.has_value()) << over_stop.error().message;
    EXPECT_EQ(over_stop->instruction_pointer, 0x400104ULL);

    // Step out on AArch64 uses link register `x30` (0x400104).
    ASSERT_TRUE(dbg.write_register(tid, "pc", 0x400200ULL).has_value());
    ASSERT_TRUE(dbg.write_register(tid, "x30", 0x400104ULL).has_value());
    ASSERT_TRUE(dbg.step_out(tid).has_value());
    auto out_stop = dbg.wait_for_stop(std::chrono::milliseconds{500});
    ASSERT_TRUE(out_stop.has_value()) << out_stop.error().message;
    EXPECT_EQ(out_stop->instruction_pointer, 0x400104ULL);

    // Now simulate stub replying empty `""` unsupported to Z2 watchpoints -> capability degrades honestly.
    stub->hw_bp_unsupported = true;
    auto unsupported_wp = dbg.add_hardware_breakpoint(
        0x404010ULL,
        debugger::BreakpointKind::HardwareWrite,
        4u,
        "unsupported_wp");
    EXPECT_FALSE(unsupported_wp.has_value());
    EXPECT_EQ(unsupported_wp.status.availability, Availability::Unavailable);

    const Capability hw_cap = gdb_dbg->capability_matrix().get(Operation::HardwareWatchpoints);
    EXPECT_EQ(hw_cap.state, SupportState::Unsupported);
    EXPECT_FALSE(hw_cap.provider_available);
}

TEST(GdbRemoteDebugTest, Riscv64LegacyContinueStepFallbackAndCtrlCAsyncInterrupt) {
    auto stub = make_riscv64_stub();
    // Force legacy `Hc` + `c`/`s` path by returning empty `""` to `vCont?`.
    stub->vcont_reply.clear();
    stub->hold_running_until_interrupt = true;

    stub->on_resume = [](FakeDebugStubState& s, std::string_view cmd) -> std::optional<std::string> {
        const std::uint64_t pc = s.get_reg(3u);
        if (cmd == "s" || cmd.starts_with("S")) {
            s.set_reg(3u, pc + 4u);
            return std::string{"S05"};
        }
        for (const ArmedStubBp& bp : s.armed_bps) {
            if (bp.type == 0u) {
                s.set_reg(3u, bp.addr);
                return std::format("T05thread:{};", s.active_thread);
            }
        }
        return std::nullopt;
    };

    auto opened = GdbRemoteBackend::open_debug(
        std::make_unique<FakeDebugRspTransport>(stub),
        ExplicitDebugConsent{.acknowledged_target_mutation = true});
    ASSERT_TRUE(opened.has_value()) << opened.error().message;
    auto& dbg = **opened;
    auto* gdb_dbg = dynamic_cast<IGdbRemoteDebugSession*>(&dbg);
    ASSERT_NE(gdb_dbg, nullptr);
    const ThreadId tid = dbg.stop_status().active_tid;
    ASSERT_NE(tid, 0u);

    EXPECT_FALSE(gdb_dbg->vcont_capabilities().supported);

    // Legacy `c` + concurrent `0x03` (`Ctrl-C`) asynchronous interrupt while `wait_for_stop` blocks.
    ASSERT_TRUE(dbg.continue_execution(false).has_value());
    EXPECT_EQ(dbg.state(), debugger::DebugSessionState::Running);

    std::jthread interrupter([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds{30});
        EXPECT_TRUE(dbg.pause_execution().has_value());
    });

    auto irq_stop = dbg.wait_for_stop(std::chrono::milliseconds{1000});
    interrupter.join();
    ASSERT_TRUE(irq_stop.has_value()) << irq_stop.error().message;
    ASSERT_TRUE(irq_stop->last_event.has_value());
    EXPECT_EQ(irq_stop->last_event->kind, debugger::DebugEventKind::ExceptionOrSignal);
    EXPECT_EQ(irq_stop->last_event->signal_or_exception_code, 2);
    EXPECT_EQ(stub->interrupt_count, 1u);
    EXPECT_EQ(dbg.state(), debugger::DebugSessionState::Paused);

    // Verify `Hc` + `s` single-step fallback and `S05` stop-reply parsing.
    stub->hold_running_until_interrupt = false;
    ASSERT_TRUE(dbg.step_into(tid).has_value());
    auto step_stop = dbg.wait_for_stop(std::chrono::milliseconds{500});
    ASSERT_TRUE(step_stop.has_value()) << step_stop.error().message;
    ASSERT_TRUE(step_stop->last_event.has_value());
    EXPECT_EQ(step_stop->last_event->kind, debugger::DebugEventKind::SingleStepCompleted);
    EXPECT_EQ(step_stop->instruction_pointer, 0x10004ULL);

    const bool saw_hc = std::ranges::any_of(stub->received_commands, [](const std::string& c) {
        return c.starts_with("Hc");
    });
    const bool saw_legacy_c = std::ranges::any_of(stub->received_commands, [](const std::string& c) {
        return c == "c";
    });
    const bool saw_legacy_s = std::ranges::any_of(stub->received_commands, [](const std::string& c) {
        return c == "s";
    });
    EXPECT_TRUE(saw_hc);
    EXPECT_TRUE(saw_legacy_c);
    EXPECT_TRUE(saw_legacy_s);

    // Step over & step out on RISC-V 64 (`jal ra, +0x100` at 0x10000 -> fallthrough 0x10004).
    ASSERT_TRUE(dbg.write_register(tid, "pc", 0x10000ULL).has_value());
    ASSERT_TRUE(dbg.step_over(tid).has_value());
    auto over_stop = dbg.wait_for_stop(std::chrono::milliseconds{500});
    ASSERT_TRUE(over_stop.has_value()) << over_stop.error().message;
    EXPECT_EQ(over_stop->instruction_pointer, 0x10004ULL);

    ASSERT_TRUE(dbg.write_register(tid, "pc", 0x10100ULL).has_value());
    ASSERT_TRUE(dbg.write_register(tid, "ra", 0x10004ULL).has_value());
    ASSERT_TRUE(dbg.step_out(tid).has_value());
    auto out_stop = dbg.wait_for_stop(std::chrono::milliseconds{500});
    ASSERT_TRUE(out_stop.has_value()) << out_stop.error().message;
    EXPECT_EQ(out_stop->instruction_pointer, 0x10004ULL);
}

TEST(GdbRemoteDebugTest, PowerPc64BigEndianRegisterWritesStepOverStepOutAndGFallback) {
    auto stub = make_ppc64_be_stub();
    stub->on_resume = [](FakeDebugStubState& s, std::string_view /*cmd*/) -> std::optional<std::string> {
        for (const ArmedStubBp& bp : s.armed_bps) {
            if (bp.type == 0u) {
                s.set_reg(2u, bp.addr);
                return std::format("T05swbreak:;02:{};thread:{};",
                                   encode_reg_hex(bp.addr, 8u, Endianness::Big),
                                   s.active_thread);
            }
        }
        return std::nullopt;
    };

    auto opened = GdbRemoteBackend::open_debug(
        std::make_unique<FakeDebugRspTransport>(stub),
        ExplicitDebugConsent{.acknowledged_target_mutation = true});
    ASSERT_TRUE(opened.has_value()) << opened.error().message;
    auto& dbg = **opened;
    const ThreadId tid = dbg.stop_status().active_tid;
    ASSERT_NE(tid, 0u);

    EXPECT_EQ(dbg.session().info().architecture, Architecture::PowerPC64);
    EXPECT_EQ(dbg.session().info().endianness, Endianness::Big);

    // Big-endian 64-bit `P` register write: MSB-first hex (`0102030405060708`), NOT little-endian.
    ASSERT_TRUE(dbg.write_register(tid, "r0", 0x0102030405060708ULL).has_value());
    EXPECT_EQ(stub->get_reg(0u), 0x0102030405060708ULL);
    EXPECT_NE(std::ranges::find(stub->received_commands, "P0=0102030405060708"),
              stub->received_commands.end());

    // Big-endian 32-bit `P` register write (`cr`, bitsize=32 -> 8 hex digits `deadbeef`).
    ASSERT_TRUE(dbg.write_register(tid, "cr", 0xDEADBEEFULL).has_value());
    EXPECT_EQ(stub->get_reg(4u), 0xDEADBEEFu);
    EXPECT_NE(std::ranges::find(stub->received_commands, "P4=deadbeef"),
              stub->received_commands.end());

    // Fallback to full `G` packet when `P` replies empty `""`.
    stub->p_write_unsupported = true;
    ASSERT_TRUE(dbg.write_register(tid, "r0", 0xCAFEBABE11223344ULL).has_value());
    EXPECT_EQ(stub->get_reg(0u), 0xCAFEBABE11223344ULL);

    stub->p_write_unsupported = false;

    // PowerPC64 BE `step_over` across `bl .+0x100` at 0x10000400 -> temporary Z0 at 0x10000404.
    ASSERT_TRUE(dbg.write_register(tid, "pc", 0x10000400ULL).has_value());
    ASSERT_TRUE(dbg.step_over(tid).has_value());
    auto over_stop = dbg.wait_for_stop(std::chrono::milliseconds{500});
    ASSERT_TRUE(over_stop.has_value()) << over_stop.error().message;
    EXPECT_EQ(over_stop->instruction_pointer, 0x10000404ULL);

    // PowerPC64 BE `step_out` via `lr` (0x10000404).
    ASSERT_TRUE(dbg.write_register(tid, "pc", 0x10000500ULL).has_value());
    ASSERT_TRUE(dbg.write_register(tid, "lr", 0x10000404ULL).has_value());
    ASSERT_TRUE(dbg.step_out(tid).has_value());
    auto out_stop = dbg.wait_for_stop(std::chrono::milliseconds{500});
    ASSERT_TRUE(out_stop.has_value()) << out_stop.error().message;
    EXPECT_EQ(out_stop->instruction_pointer, 0x10000404ULL);
}

TEST(GdbRemoteDebugTest, TruthfulDetachRetainsStateWhenBreakpointDisarmOrDetachPacketFails) {
    auto stub = make_x86_64_stub();
    auto opened = GdbRemoteBackend::open_debug(
        std::make_unique<FakeDebugRspTransport>(stub),
        ExplicitDebugConsent{.acknowledged_target_mutation = true});
    ASSERT_TRUE(opened.has_value()) << opened.error().message;
    auto& dbg = **opened;

    auto bp = dbg.add_software_breakpoint(0x401050ULL, "guarded_bp");
    ASSERT_TRUE(bp.has_value());
    ASSERT_TRUE(stub->has_armed_bp(0u, 0x401050ULL));

    // 1. Failing `z0` disarm must NOT send `D` or claim `Detached`, and must retain the armed breakpoint.
    stub->fail_z0_disarm = true;
    auto failed_z0 = dbg.detach();
    ASSERT_FALSE(failed_z0.has_value());
    EXPECT_EQ(dbg.state(), debugger::DebugSessionState::Paused);
    EXPECT_EQ(dbg.breakpoints().size(), 1u);
    EXPECT_TRUE(dbg.breakpoints()[0].enabled);
    EXPECT_EQ(std::ranges::find(stub->received_commands, "D"), stub->received_commands.end());

    // 2. Allow `z0` to succeed, but fail `D` -> session stays attached (`Paused`) and returns explicit Error.
    stub->fail_z0_disarm = false;
    stub->fail_detach = true;
    auto failed_d = dbg.detach();
    ASSERT_FALSE(failed_d.has_value());
    EXPECT_EQ(dbg.state(), debugger::DebugSessionState::Paused);
    EXPECT_FALSE(stub->has_armed_bp(0u, 0x401050ULL));

    // 3. Once `D` succeeds, session transitions cleanly to `Detached`.
    stub->fail_detach = false;
    auto ok_detach = dbg.detach();
    ASSERT_TRUE(ok_detach.has_value()) << ok_detach.error().message;
    EXPECT_EQ(dbg.state(), debugger::DebugSessionState::Detached);
}

TEST(GdbRemoteDebugTest, BinaryModelRemoteAttachAndExecutionTimelineFlow) {
    // 1. Consent rejection via BinaryModel::connect_gdb_remote_debug.
    {
        auto denied_stub = make_x86_64_stub();
        viewer::BinaryModel model;
        auto res = model.connect_gdb_remote_debug(
            std::make_unique<FakeDebugRspTransport>(denied_stub),
            ExplicitDebugConsent{.acknowledged_target_mutation = false});
        EXPECT_FALSE(res.has_value());
        EXPECT_FALSE(model.is_live_process());
        EXPECT_FALSE(model.is_debug_session());
        EXPECT_TRUE(denied_stub->received_commands.empty());
    }

    // 2. Read-only attach via BinaryModel::connect_gdb_remote_readonly marks breakpoints Unsupported.
    {
        auto ro_stub = make_x86_64_stub();
        viewer::BinaryModel ro_model;
        auto ro_res = ro_model.connect_gdb_remote_readonly(
            std::make_unique<FakeDebugRspTransport>(ro_stub));
        ASSERT_TRUE(ro_res.has_value()) << ro_res.error().message;
        EXPECT_TRUE(ro_model.is_live_process());
        EXPECT_FALSE(ro_model.is_debug_session());
        EXPECT_EQ(ro_model.target_instance_id().backend, BackendKind::RemoteGdbRsp);
        EXPECT_EQ(ro_model.capability_matrix().get(Operation::SoftwareBreakpoints).state,
                  SupportState::Unsupported);
    }

    // 3. Opt-in debug attach via BinaryModel::connect_gdb_remote_debug + ExecutionTimeline event flow.
    auto stub = make_x86_64_stub();
    int resume_step = 0;
    stub->on_resume = [&](FakeDebugStubState& s, std::string_view /*cmd*/) -> std::optional<std::string> {
        ++resume_step;
        if (resume_step == 1) {
            // Emit RSP console debug output (`O` packet) before breakpoint stop!
            const std::string msg = "hello-rsp\n";
            const auto bytes = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size());
            s.enqueue_frame_locked("O" + hex_encode_bytes(bytes));
            s.set_reg(3u, 0x401100ULL);
            return std::format("T05swbreak:;03:{};thread:{};",
                               encode_reg_hex(0x401100ULL, 8u, Endianness::Little),
                               s.active_thread);
        }
        return "W00";
    };

    viewer::BinaryModel model;
    auto connected = model.connect_gdb_remote_debug(
        std::make_unique<FakeDebugRspTransport>(stub),
        ExplicitDebugConsent{.acknowledged_target_mutation = true});
    ASSERT_TRUE(connected.has_value()) << connected.error().message;
    ASSERT_TRUE(model.is_live_process());
    ASSERT_TRUE(model.is_debug_session());
    EXPECT_EQ(model.target_instance_id().backend, BackendKind::RemoteGdbRsp);
    EXPECT_EQ(model.capability_matrix().get(Operation::SoftwareBreakpoints).state,
              SupportState::SupportedValidated);

    // Initial attach stop event already flowed into ExecutionTimeline.
    EXPECT_GE(model.execution_timeline().size(), 1u);

    auto toggled_on = model.toggle_software_breakpoint(0x401100ULL, "remote_bp");
    ASSERT_TRUE(toggled_on.has_value()) << toggled_on.error().message;
    EXPECT_TRUE(*toggled_on);
    EXPECT_EQ(model.debug_breakpoints().size(), 1u);

    auto* dbg = model.debug_session();
    ASSERT_NE(dbg, nullptr);
    ASSERT_TRUE(dbg->continue_execution(false).has_value());
    auto stop1 = dbg->wait_for_stop(std::chrono::milliseconds{500});
    ASSERT_TRUE(stop1.has_value());
    const auto synced_ip = model.sync_debugger_stop_state();
    ASSERT_TRUE(synced_ip.has_value());
    EXPECT_EQ(*synced_ip, 0x401100ULL);

    // Degrade hardware watchpoint support via empty `""` reply and verify BinaryModel capability updates.
    stub->hw_bp_unsupported = true;
    auto hw_res = dbg->add_hardware_breakpoint(
        0x402000ULL,
        debugger::BreakpointKind::HardwareWrite,
        4u,
        "degraded_wp");
    EXPECT_FALSE(hw_res.has_value());
    model.refresh_debug_breakpoints();
    EXPECT_EQ(model.capability_matrix().get(Operation::HardwareWatchpoints).state,
              SupportState::Unsupported);

    // Resume to W00 exit and sync into ExecutionTimeline.
    ASSERT_TRUE(dbg->continue_execution(false).has_value());
    auto stop2 = dbg->wait_for_stop(std::chrono::milliseconds{500});
    ASSERT_TRUE(stop2.has_value());
    (void)model.sync_debugger_stop_state();
    EXPECT_EQ(dbg->state(), debugger::DebugSessionState::Exited);

    bool saw_bp_hit = false;
    bool saw_debug_output = false;
    bool saw_exit = false;
    for (const TimelineEvent& ev : model.execution_timeline().events()) {
        if (const auto* dev = std::get_if<debugger::DebugEvent>(&ev.payload); dev != nullptr) {
            if (dev->kind == debugger::DebugEventKind::BreakpointHit && dev->address == 0x401100ULL) {
                saw_bp_hit = true;
            }
            if (dev->kind == debugger::DebugEventKind::DebugOutput &&
                dev->summary.find("hello-rsp") != std::string::npos) {
                saw_debug_output = true;
            }
            if (dev->kind == debugger::DebugEventKind::ProcessExited && dev->exit_code == 0) {
                saw_exit = true;
            }
        }
    }
    EXPECT_TRUE(saw_bp_hit);
    EXPECT_TRUE(saw_debug_output);
    EXPECT_TRUE(saw_exit);
}

TEST(GdbRemoteDebugTest, ClientInjectedSoftwareTrapStepsOffOnContinueAndUsesSortedGFallback) {
    auto stub = make_x86_64_stub();
    // Declare `rip` (regnum=3) BEFORE `rax`/`rbx`/`rsp` in target.xml while the wire `g`/`G`
    // buffer remains ordered by ascending `regnum` (0, 1, 2, 3, 4).
    stub->target_xml =
        "<target version=\"1.0\">"
        "<architecture>i386:x86-64</architecture>"
        "<osabi>GNU/Linux</osabi>"
        "<feature name=\"org.gnu.gdb.i386.core\">"
        "<reg name=\"rip\" bitsize=\"64\" regnum=\"3\" type=\"code_ptr\"/>"
        "<reg name=\"rax\" bitsize=\"64\" regnum=\"0\"/>"
        "<reg name=\"rbx\" bitsize=\"64\" regnum=\"1\"/>"
        "<reg name=\"rsp\" bitsize=\"64\" regnum=\"2\" type=\"data_ptr\"/>"
        "<reg name=\"eflags\" bitsize=\"32\" regnum=\"4\"/>"
        "</feature>"
        "</target>";

    // Force client-injected `0xCC` (`M` fallback) and `G`-packet register writes (`P` unsupported).
    stub->z0_unsupported = true;
    stub->p_write_unsupported = true;
    stub->set_reg(3u, 0x401000ULL);

    // Byte-accurate x86-64 NOP (0x90) / INT3 (0xCC) execution model:
    // If `continue_execution()` fails to step off an enabled client-injected `0xCC`, the stub
    // immediately re-hits `0xCC` at the exact same address forever instead of reaching the next BP.
    stub->on_resume = [](FakeDebugStubState& s, std::string_view cmd) -> std::optional<std::string> {
        const bool is_step = cmd.starts_with("vCont;s") || cmd == "s";
        if (is_step) {
            const std::uint64_t pc = s.get_reg(3u);
            const auto insn = s.read_mem(pc, 1u);
            if (!insn.has_value()) {
                return std::format("T0bthread:{};", s.active_thread);
            }
            s.set_reg(3u, pc + 1u);
            return std::format("T0503:{};thread:{};",
                               encode_reg_hex(pc + 1u, 8u, Endianness::Little),
                               s.active_thread);
        }

        for (std::size_t steps = 0u; steps < 32u; ++steps) {
            const std::uint64_t pc = s.get_reg(3u);
            if (pc >= 0x401008ULL) {
                return std::string{"W00"};
            }
            const auto insn = s.read_mem(pc, 1u);
            if (!insn.has_value()) {
                return std::format("T0bthread:{};", s.active_thread);
            }
            s.set_reg(3u, pc + 1u);
            if ((*insn)[0] == 0xCCu) {
                return std::format("T0503:{};thread:{};",
                                   encode_reg_hex(pc + 1u, 8u, Endianness::Little),
                                   s.active_thread);
            }
        }
        return std::string{"T05"};
    };

    auto opened = GdbRemoteBackend::open_debug(
        std::make_unique<FakeDebugRspTransport>(stub),
        ExplicitDebugConsent{.acknowledged_target_mutation = true});
    ASSERT_TRUE(opened.has_value()) << opened.error().message;
    auto& dbg = **opened;
    const ThreadId tid = dbg.stop_status().active_tid;
    ASSERT_NE(tid, 0u);

    auto bp1 = dbg.add_software_breakpoint(0x401002ULL, "client_sw_bp_1");
    ASSERT_TRUE(bp1.has_value()) << bp1.error().message;
    auto bp2 = dbg.add_software_breakpoint(0x401005ULL, "client_sw_bp_2");
    ASSERT_TRUE(bp2.has_value()) << bp2.error().message;

    // Confirm client injected 0xCC via `M` fallback at both addresses.
    ASSERT_EQ(stub->read_mem(0x401002ULL, 1u), (std::optional<std::vector<std::uint8_t>>{{0xCCu}}));
    ASSERT_EQ(stub->read_mem(0x401005ULL, 1u), (std::optional<std::vector<std::uint8_t>>{{0xCCu}}));

    // 1. First continue from 0x401000 hits 0x401002 (`pc` = 0x401003) and rewinds `rip` to 0x401002
    // via `G` fallback using `regnum`-sorted layout without corrupting `rax`/`rbx`/`rsp`!
    ASSERT_TRUE(dbg.continue_execution(false).has_value());
    auto stop1 = dbg.wait_for_stop(std::chrono::milliseconds{500});
    ASSERT_TRUE(stop1.has_value()) << stop1.error().message;
    EXPECT_EQ(stop1->instruction_pointer, 0x401002ULL);
    EXPECT_EQ(stub->get_reg(3u), 0x401002ULL);
    EXPECT_EQ(stub->get_reg(0u), 0x1111ULL);
    EXPECT_EQ(stub->get_reg(1u), 0x2222ULL);
    EXPECT_EQ(stub->get_reg(2u), 0x7fffffffe000ULL);
    ASSERT_TRUE(stop1->last_event.has_value());
    EXPECT_EQ(stop1->last_event->kind, debugger::DebugEventKind::BreakpointHit);
    EXPECT_EQ(stop1->last_event->breakpoint_id, bp1->id);

    // 2. Continuing again while parked on 0x401002 must temporarily restore 0x90, single-step to
    // 0x401003, re-arm 0xCC at 0x401002, and continue on to hit bp2 at 0x401005!
    ASSERT_TRUE(dbg.continue_execution(false).has_value());
    auto stop2 = dbg.wait_for_stop(std::chrono::milliseconds{500});
    ASSERT_TRUE(stop2.has_value()) << stop2.error().message;
    EXPECT_EQ(stop2->instruction_pointer, 0x401005ULL);
    EXPECT_EQ(stub->get_reg(3u), 0x401005ULL);
    ASSERT_TRUE(stop2->last_event.has_value());
    EXPECT_EQ(stop2->last_event->kind, debugger::DebugEventKind::BreakpointHit);
    EXPECT_EQ(stop2->last_event->breakpoint_id, bp2->id);
    // Trap byte at 0x401002 was re-inserted after stepping off!
    EXPECT_EQ(stub->read_mem(0x401002ULL, 1u), (std::optional<std::vector<std::uint8_t>>{{0xCCu}}));

    // 3. `step_into` while parked on bp2 (0x401005) steps off 0x401005 cleanly to 0x401006
    // and re-inserts 0xCC at 0x401005.
    ASSERT_TRUE(dbg.step_into(tid).has_value());
    auto stop3 = dbg.wait_for_stop(std::chrono::milliseconds{500});
    ASSERT_TRUE(stop3.has_value()) << stop3.error().message;
    EXPECT_EQ(stop3->instruction_pointer, 0x401006ULL);
    ASSERT_TRUE(stop3->last_event.has_value());
    EXPECT_EQ(stop3->last_event->kind, debugger::DebugEventKind::SingleStepCompleted);
    EXPECT_EQ(stub->read_mem(0x401005ULL, 1u), (std::optional<std::vector<std::uint8_t>>{{0xCCu}}));
}

} // namespace
} // namespace peelf
