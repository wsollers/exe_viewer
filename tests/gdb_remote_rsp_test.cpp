#include <peelf/gdb_remote.hpp>

#include <peelf/capability_matrix.hpp>
#include <peelf/process_internals.hpp>
#include <peelf/process_snapshot.hpp>

#include <gtest/gtest.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <memory>
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

[[nodiscard]] std::string hex_bytes(std::span<const std::uint8_t> bytes) {
    static constexpr std::string_view kHex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2u);
    for (const std::uint8_t b : bytes) {
        out.push_back(kHex[static_cast<std::size_t>((b >> 4u) & 0xFu)]);
        out.push_back(kHex[static_cast<std::size_t>(b & 0xFu)]);
    }
    return out;
}

[[nodiscard]] std::string le_hex_u64(std::uint64_t v) {
    std::array<std::uint8_t, 8> b{};
    for (std::size_t i = 0; i < 8u; ++i) {
        b[i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
    }
    return hex_bytes(b);
}

[[nodiscard]] std::string le_hex_u32(std::uint32_t v) {
    std::array<std::uint8_t, 4> b{};
    for (std::size_t i = 0; i < 4u; ++i) {
        b[i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
    }
    return hex_bytes(b);
}

[[nodiscard]] std::string be_hex_u64(std::uint64_t v) {
    std::array<std::uint8_t, 8> b{};
    for (std::size_t i = 0; i < 8u; ++i) {
        b[7u - i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
    }
    return hex_bytes(b);
}

[[nodiscard]] std::string be_hex_u32(std::uint32_t v) {
    std::array<std::uint8_t, 4> b{};
    for (std::size_t i = 0; i < 4u; ++i) {
        b[3u - i] = static_cast<std::uint8_t>((v >> (i * 8u)) & 0xFFu);
    }
    return hex_bytes(b);
}

struct StubSharedState {
    bool open{true};
    bool no_ack_mode{false};
    std::size_t max_read_chunk{4096};

    // Fault injection counters
    std::size_t nak_next_commands{0};
    std::size_t corrupt_next_reply_checksums{0};

    // Audit log of every decoded client command received by the stub and raw wire bytes
    std::vector<std::string> received_commands{};
    std::string raw_tx_wire{};
    std::size_t received_ack_count{0};
    std::size_t received_nak_count{0};

    // Configurable stub state
    std::string qsupported_reply{
        "PacketSize=400;QStartNoAckMode+;multiprocess+;qXfer:features:read+;"
        "qXfer:memory-map:read+;qXfer:libraries-svr4:read+;qXfer:auxv:read+"};
    std::string halt_reply{"T05thread:p10.20;"};
    std::unordered_map<std::string, std::string> features_annexes{};
    std::optional<std::string> memory_map_xml{};
    std::optional<std::string> libraries_svr4_xml{};
    std::optional<std::string> libraries_xml{};
    std::optional<std::string> auxv_binary{};
    std::vector<std::string> thread_info_pages{};
    std::string qc_reply{};
    std::string current_hg{"p10.20"};
    std::unordered_map<std::string, std::string> g_replies_by_thread{};
    std::string default_g_reply{};
    std::map<std::uint32_t, std::string> p_replies_by_regnum{};
    std::map<std::uint64_t, std::vector<std::uint8_t>> memory_segments{};
    std::function<std::optional<std::string>(std::string_view)> custom_handler{};

    std::deque<std::uint8_t> tx_to_client{};
    std::string rx_from_client{};

    void enqueue_raw(std::string_view s) {
        for (const char ch : s) {
            tx_to_client.push_back(static_cast<std::uint8_t>(ch));
        }
    }

    void enqueue_reply_frame(std::string_view raw_payload) {
        std::string frame = rsp_encode_frame(raw_payload);
        if (corrupt_next_reply_checksums > 0u && frame.size() >= 2u) {
            --corrupt_next_reply_checksums;
            frame[frame.size() - 1u] = (frame.back() == '0') ? '1' : '0';
        }
        enqueue_raw(frame);
    }

    [[nodiscard]] std::string handle_qxfer_slice(
        std::string_view content,
        std::string_view off_len) const {
        const std::size_t comma = off_len.find(',');
        if (comma == std::string_view::npos) {
            return "E01";
        }
        const std::string off_s(off_len.substr(0, comma));
        const std::string len_s(off_len.substr(comma + 1u));
        const auto off = static_cast<std::size_t>(std::stoull(off_s, nullptr, 16));
        const auto len = static_cast<std::size_t>(std::stoull(len_s, nullptr, 16));
        if (off >= content.size()) {
            return "l";
        }
        const std::size_t avail = content.size() - off;
        const std::size_t take = std::min(avail, len);
        const char prefix = (off + take >= content.size()) ? 'l' : 'm';
        std::string out(1u, prefix);
        out.append(content.substr(off, take));
        return out;
    }

    [[nodiscard]] std::string dispatch_command(std::string_view cmd, std::size_t& thread_page_idx) {
        received_commands.emplace_back(cmd);

        if (custom_handler) {
            if (auto custom = custom_handler(cmd); custom.has_value()) {
                return *custom;
            }
        }

        if (cmd.starts_with("qSupported")) {
            return qsupported_reply;
        }
        if (cmd == "QStartNoAckMode") {
            return "OK";
        }
        if (cmd == "?") {
            return halt_reply;
        }
        if (cmd.starts_with("qXfer:features:read:")) {
            const std::string_view rest = cmd.substr(std::string_view{"qXfer:features:read:"}.size());
            const std::size_t colon = rest.find(':');
            if (colon == std::string_view::npos) {
                return "E01";
            }
            const std::string annex(rest.substr(0, colon));
            const auto it = features_annexes.find(annex);
            if (it == features_annexes.end()) {
                return "";
            }
            return handle_qxfer_slice(it->second, rest.substr(colon + 1u));
        }
        if (cmd.starts_with("qXfer:memory-map:read::")) {
            if (!memory_map_xml.has_value()) {
                return "";
            }
            return handle_qxfer_slice(
                *memory_map_xml,
                cmd.substr(std::string_view{"qXfer:memory-map:read::"}.size()));
        }
        if (cmd.starts_with("qXfer:libraries-svr4:read::")) {
            if (!libraries_svr4_xml.has_value()) {
                return "";
            }
            return handle_qxfer_slice(
                *libraries_svr4_xml,
                cmd.substr(std::string_view{"qXfer:libraries-svr4:read::"}.size()));
        }
        if (cmd.starts_with("qXfer:libraries:read::")) {
            if (!libraries_xml.has_value()) {
                return "";
            }
            return handle_qxfer_slice(
                *libraries_xml,
                cmd.substr(std::string_view{"qXfer:libraries:read::"}.size()));
        }
        if (cmd.starts_with("qXfer:auxv:read::")) {
            if (!auxv_binary.has_value()) {
                return "";
            }
            return handle_qxfer_slice(
                *auxv_binary,
                cmd.substr(std::string_view{"qXfer:auxv:read::"}.size()));
        }
        if (cmd == "qfThreadInfo") {
            thread_page_idx = 0u;
            if (thread_info_pages.empty()) {
                return "";
            }
            return thread_info_pages[thread_page_idx++];
        }
        if (cmd == "qsThreadInfo") {
            if (thread_page_idx < thread_info_pages.size()) {
                return thread_info_pages[thread_page_idx++];
            }
            return "l";
        }
        if (cmd == "qC") {
            return qc_reply;
        }
        if (cmd.starts_with("Hg")) {
            current_hg = std::string(cmd.substr(2u));
            return "OK";
        }
        if (cmd == "g") {
            if (const auto it = g_replies_by_thread.find(current_hg);
                it != g_replies_by_thread.end()) {
                return it->second;
            }
            return default_g_reply;
        }
        if (cmd.starts_with("p")) {
            const auto regnum = static_cast<std::uint32_t>(
                std::stoul(std::string(cmd.substr(1u)), nullptr, 16));
            if (const auto it = p_replies_by_regnum.find(regnum);
                it != p_replies_by_regnum.end()) {
                return it->second;
            }
            return "";
        }
        if (cmd.starts_with("m")) {
            const std::string_view spec = cmd.substr(1u);
            const std::size_t comma = spec.find(',');
            if (comma == std::string_view::npos) {
                return "E01";
            }
            const std::uint64_t addr =
                std::stoull(std::string(spec.substr(0, comma)), nullptr, 16);
            const std::size_t len =
                static_cast<std::size_t>(std::stoull(std::string(spec.substr(comma + 1u)), nullptr, 16));
            std::vector<std::uint8_t> out;
            out.reserve(len);
            for (std::size_t i = 0; i < len; ++i) {
                const std::uint64_t cur = addr + i;
                bool found = false;
                for (const auto& [base, data] : memory_segments) {
                    if (cur >= base && (cur - base) < data.size()) {
                        out.push_back(data[static_cast<std::size_t>(cur - base)]);
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    break;
                }
            }
            if (out.empty()) {
                return "E14";
            }
            return hex_bytes(out);
        }
        return "";
    }

    void process_incoming_bytes(std::span<const std::uint8_t> data) {
        for (const std::uint8_t b : data) {
            raw_tx_wire.push_back(static_cast<char>(b));
            rx_from_client.push_back(static_cast<char>(b));
        }

        while (!rx_from_client.empty()) {
            const char front = rx_from_client.front();
            if (front == '+') {
                ++received_ack_count;
                rx_from_client.erase(0, 1u);
                if (pending_no_ack_transition_) {
                    no_ack_mode = true;
                    pending_no_ack_transition_ = false;
                }
                continue;
            }
            if (front == '-') {
                ++received_nak_count;
                rx_from_client.erase(0, 1u);
                // Retransmit last reply payload cleanly.
                enqueue_reply_frame(last_reply_payload_);
                continue;
            }
            if (front != '$') {
                rx_from_client.erase(0, 1u);
                continue;
            }

            const std::size_t hash = rx_from_client.find('#', 1u);
            if (hash == std::string::npos || hash + 2u >= rx_from_client.size()) {
                break;  // Wait for complete packet frame
            }

            const std::string wire_body = rx_from_client.substr(1u, hash - 1u);
            const std::string csum_hex = rx_from_client.substr(hash + 1u, 2u);
            rx_from_client.erase(0, hash + 3u);

            const auto expected_csum =
                static_cast<std::uint8_t>(std::stoul(csum_hex, nullptr, 16));
            if (expected_csum != compute_rsp_checksum(wire_body) || nak_next_commands > 0u) {
                if (nak_next_commands > 0u) {
                    --nak_next_commands;
                }
                if (!no_ack_mode) {
                    enqueue_raw("-");
                }
                continue;
            }

            if (!no_ack_mode) {
                enqueue_raw("+");
            }

            auto decoded = rsp_decode_wire_payload(wire_body);
            if (!decoded.has_value()) {
                last_reply_payload_ = "E01";
                enqueue_reply_frame(last_reply_payload_);
                continue;
            }

            const bool was_start_no_ack = (*decoded == "QStartNoAckMode");
            last_reply_payload_ = dispatch_command(*decoded, thread_page_cursor_);
            if (was_start_no_ack && last_reply_payload_ == "OK") {
                pending_no_ack_transition_ = true;
            }
            enqueue_reply_frame(last_reply_payload_);
        }
    }

private:
    std::size_t thread_page_cursor_{0};
    std::string last_reply_payload_{};
    bool pending_no_ack_transition_{false};
};

class FakeInMemoryRspTransport final : public IRspTransport {
public:
    explicit FakeInMemoryRspTransport(std::shared_ptr<StubSharedState> state) noexcept
        : state_(std::move(state)) {}

    [[nodiscard]] Result<RspReadOutcome> read_some(
        std::span<std::uint8_t> buffer,
        std::chrono::milliseconds /*timeout*/,
        std::stop_token stop_token) override {
        if (!is_open()) {
            return make_error("Fake transport closed");
        }
        if (stop_token.stop_requested()) {
            return RspReadOutcome{RspIoStatus::Cancelled, 0u};
        }
        if (state_->tx_to_client.empty()) {
            return RspReadOutcome{RspIoStatus::Timeout, 0u};
        }
        const std::size_t n =
            std::min({buffer.size(), state_->tx_to_client.size(), state_->max_read_chunk});
        for (std::size_t i = 0; i < n; ++i) {
            buffer[i] = state_->tx_to_client.front();
            state_->tx_to_client.pop_front();
        }
        return RspReadOutcome{RspIoStatus::Ok, n};
    }

    [[nodiscard]] Result<void> write_all(
        std::span<const std::uint8_t> data,
        std::chrono::milliseconds /*timeout*/,
        std::stop_token stop_token) override {
        if (!is_open()) {
            return make_error("Fake transport closed");
        }
        if (stop_token.stop_requested()) {
            return make_error("Fake transport write cancelled");
        }
        state_->process_incoming_bytes(data);
        return {};
    }

    [[nodiscard]] bool is_open() const noexcept override {
        return state_ != nullptr && state_->open;
    }

    void close() noexcept override {
        if (state_ != nullptr) {
            state_->open = false;
        }
    }

    [[nodiscard]] std::string endpoint_description() const override {
        return "fake-inmem:0";
    }

private:
    std::shared_ptr<StubSharedState> state_;
};

// ---------------------------------------------------------------------------
// 1. Escaping, RLE, fragmentation, NAK retry, & QStartNoAckMode tests
// ---------------------------------------------------------------------------

TEST(GdbRemoteRspTest, EscapingAndRunLengthDecodingHandleSpecialBytesAndBounds) {
    const std::string raw_special = "A$B#C}D*E";
    const std::string escaped = rsp_escape_payload(raw_special);
    EXPECT_EQ(escaped.find('$'), std::string::npos);
    EXPECT_EQ(escaped.find('#'), std::string::npos);
    EXPECT_EQ(escaped.find('*'), std::string::npos);

    auto roundtrip = rsp_decode_wire_payload(escaped);
    ASSERT_TRUE(roundtrip.has_value());
    EXPECT_EQ(*roundtrip, raw_special);

    // Escaped '*' (0x7d 0x0a) followed by ' ' must NOT trigger RLE!
    std::string escaped_star_wire = "Z";
    escaped_star_wire.push_back('}');
    escaped_star_wire.push_back(static_cast<char>(0x2Au ^ 0x20u));
    escaped_star_wire.push_back(' ');
    auto literal_star = rsp_decode_wire_payload(escaped_star_wire);
    ASSERT_TRUE(literal_star.has_value());
    EXPECT_EQ(*literal_star, "Z* ");

    // Standard RLE: '0' followed by "* " (repeat = 32 - 29 = 3) -> "0000"
    auto rle_short = rsp_decode_wire_payload("0* f*~");
    ASSERT_TRUE(rle_short.has_value());
    EXPECT_EQ(*rle_short, "0000" + std::string(98u, 'f'));

    // Bounded RLE bomb rejection
    auto rle_overflow = rsp_decode_wire_payload("0*~", 32u);
    EXPECT_FALSE(rle_overflow.has_value());

    // Truncated '}' escape rejection
    auto truncated_esc = rsp_decode_wire_payload("abc}");
    EXPECT_FALSE(truncated_esc.has_value());
}

TEST(GdbRemoteRspTest, FragmentationBadChecksumNakRetryAndNoAckTransition) {
    auto stub = std::make_shared<StubSharedState>();
    stub->max_read_chunk = 1u;  // Extreme 1-byte TCP stream fragmentation!
    stub->nak_next_commands = 2u;
    stub->corrupt_next_reply_checksums = 2u;

    RspClientOptions opts{};
    opts.max_retries = 3u;
    opts.request_no_ack_mode = true;

    RspClient client(std::make_unique<FakeInMemoryRspTransport>(stub), opts);
    auto caps = client.negotiate();
    ASSERT_TRUE(caps.has_value()) << caps.error().message;
    EXPECT_TRUE(caps->no_ack_mode_supported);
    EXPECT_TRUE(caps->no_ack_mode_active);
    EXPECT_TRUE(client.is_no_ack_mode());
    EXPECT_EQ(caps->packet_size, 0x400u);
    EXPECT_EQ(stub->received_nak_count, 2u);
    EXPECT_GE(stub->received_ack_count, 2u);  // qSupported ACK + final QStartNoAckMode ACK

    // Subsequent commands in QStartNoAckMode must not emit '+' ACKs.
    const std::size_t acks_before = stub->received_ack_count;
    auto halt = client.send_command("?");
    ASSERT_TRUE(halt.has_value());
    EXPECT_EQ(*halt, "T05thread:p10.20;");
    EXPECT_EQ(stub->received_ack_count, acks_before);
}

TEST(GdbRemoteRspTest, RepeatedCorruptChecksumFailsAfterBoundedRetries) {
    auto stub = std::make_shared<StubSharedState>();
    stub->corrupt_next_reply_checksums = 10u;

    RspClientOptions opts{};
    opts.max_retries = 2u;
    opts.request_no_ack_mode = false;

    RspClient client(std::make_unique<FakeInMemoryRspTransport>(stub), opts);
    auto res = client.send_command("?");
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(stub->received_nak_count, 2u);
}

// ---------------------------------------------------------------------------
// 2. Multi-arch target.xml (<xi:include>) & 'xx' unavailable register tests
// ---------------------------------------------------------------------------

TEST(GdbRemoteRspTest, TargetXmlMultiAnnexX86_64WithUnavailableXxRegisters) {
    auto stub = std::make_shared<StubSharedState>();
    stub->qsupported_reply =
        "PacketSize=80;QStartNoAckMode+;multiprocess+;qXfer:features:read+;"
        "qXfer:memory-map:read+;qXfer:libraries-svr4:read+";

    stub->features_annexes["target.xml"] = R"xml(<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target version="1.0">
  <architecture>i386:x86-64</architecture>
  <osabi>GNU/Linux</osabi>
  <xi:include href="64bit-core.xml"/>
  <xi:include href="64bit-sse.xml"/>
</target>)xml";

    stub->features_annexes["64bit-core.xml"] = R"xml(<?xml version="1.0"?>
<feature name="org.gnu.gdb.i386.core">
  <flags id="i386_eflags" size="4">
    <field name="CF" start="0" end="0"/>
    <field name="ZF" start="6" end="6"/>
    <field name="IF" start="9" end="9"/>
  </flags>
  <reg name="rax" bitsize="64" type="int64"/>
  <reg name="rbx" bitsize="64" type="int64"/>
  <reg name="rbp" bitsize="64" type="data_ptr"/>
  <reg name="rsp" bitsize="64" type="data_ptr"/>
  <reg name="rip" bitsize="64" type="code_ptr" regnum="16"/>
  <reg name="eflags" bitsize="32" type="i386_eflags" regnum="17"/>
  <reg name="fs_base" bitsize="64" type="data_ptr" regnum="58"/>
</feature>)xml";

    stub->features_annexes["64bit-sse.xml"] = R"xml(<?xml version="1.0"?>
<feature name="org.gnu.gdb.i386.sse">
  <reg name="xmm0" bitsize="128" type="vec128" group="vector" regnum="40"/>
</feature>)xml";

    // Order by regnum:
    // 0: rax = 0x1122334455667788 (valid)
    // 1: rbx = xxxxxxxxxxxxxxxx (completely unavailable — MUST NOT zero-fill!)
    // 2: rbp = 11223344xxxxxxxx (partially unavailable — MUST NOT zero-fill!)
    // 3: rsp = 0x00007fffffffe100
    // 16: rip = 0x0000555555555140
    // 17: eflags = 0x00000240 (ZF + IF)
    // 40: xmm0 = 16 bytes
    // 58: fs_base = omitted from 'g', fetched via 'p3a'!
    stub->default_g_reply =
        le_hex_u64(0x1122'3344'5566'7788ULL) +
        "xxxxxxxxxxxxxxxx" +
        "11223344xxxxxxxx" +
        le_hex_u64(0x0000'7fff'fffe'e100ULL) +
        le_hex_u64(0x0000'5555'5555'5140ULL) +
        le_hex_u32(0x0000'0240U) +
        "000102030405060708090a0b0c0d0e0f";
    stub->p_replies_by_regnum[58u] = le_hex_u64(0x0000'7fff'f7ff'0740ULL);

    auto session_res = GdbRemoteBackend::open_read_only(
        std::make_unique<FakeInMemoryRspTransport>(stub));
    ASSERT_TRUE(session_res.has_value()) << session_res.error().message;

    auto* gdb_session = dynamic_cast<IGdbRemoteSession*>(session_res->get());
    ASSERT_NE(gdb_session, nullptr);
    EXPECT_EQ(gdb_session->target_profile().architecture, Architecture::X86_64);
    EXPECT_EQ(gdb_session->target_profile().endianness, Endianness::Little);
    EXPECT_EQ(gdb_session->target_profile().os, OsKind::Linux);
    EXPECT_EQ(gdb_session->target_profile().abi, AbiKind::GnuLinux);
    EXPECT_EQ(gdb_session->target_profile().backend, BackendKind::GdbRemote);

    const auto threads_res = gdb_session->threads();
    ASSERT_TRUE(threads_res.has_value());
    ASSERT_FALSE(threads_res->empty());
    const ThreadId tid = threads_res->front().tid;

    const auto raw_regs = gdb_session->read_thread_registers(tid);
    ASSERT_TRUE(raw_regs.has_value()) << raw_regs.error().message;
    ASSERT_EQ(raw_regs->size(), 8u);

    // rax (valid)
    EXPECT_EQ((*raw_regs)[0].name, "rax");
    EXPECT_EQ((*raw_regs)[0].availability, Availability::Available);
    EXPECT_EQ((*raw_regs)[0].value_u64, 0x1122'3344'5566'7788ULL);

    // rbx ('xx' unavailable)
    EXPECT_EQ((*raw_regs)[1].name, "rbx");
    EXPECT_EQ((*raw_regs)[1].availability, Availability::Unavailable);
    EXPECT_FALSE((*raw_regs)[1].value_u64.has_value());
    EXPECT_EQ((*raw_regs)[1].formatted, "unavailable");

    // rbp (mixed hex + 'xx' partial)
    EXPECT_EQ((*raw_regs)[2].name, "rbp");
    EXPECT_EQ((*raw_regs)[2].availability, Availability::Partial);
    EXPECT_FALSE((*raw_regs)[2].value_u64.has_value());
    EXPECT_NE((*raw_regs)[2].formatted.find("xx"), std::string::npos);

    // fs_base (fetched via 'p3a')
    EXPECT_EQ((*raw_regs)[7].name, "fs_base");
    EXPECT_EQ((*raw_regs)[7].availability, Availability::Available);
    EXPECT_EQ((*raw_regs)[7].value_u64, 0x0000'7fff'f7ff'0740ULL);

    const ThreadContext ctx = gdb_session->thread_context(tid);
    EXPECT_EQ(ctx.status.availability, Availability::Partial);
    EXPECT_EQ(ctx.instruction_pointer, 0x0000'5555'5555'5140ULL);
    EXPECT_EQ(ctx.stack_pointer, 0x0000'7fff'fffe'e100ULL);
    EXPECT_EQ(ctx.frame_pointer, 0u);  // rbp was partial ('xx'), never trusted as valid 0x44332211!
    EXPECT_EQ(ctx.tls_pointer, 0x0000'7fff'f7ff'0740ULL);
    ASSERT_EQ(ctx.decoded_flags.size(), 3u);
    EXPECT_FALSE(ctx.decoded_flags[0].set);  // CF = 0
    EXPECT_TRUE(ctx.decoded_flags[1].set);   // ZF = 1
    EXPECT_TRUE(ctx.decoded_flags[2].set);   // IF = 1
}

TEST(GdbRemoteRspTest, TargetXmlMultiArchAArch64Riscv64AndBigEndianPowerPcMips) {
    // 1. AArch64 with nested annex
    {
        const std::string root_xml = R"xml(<?xml version="1.0"?>
<target version="1.0">
  <architecture>aarch64</architecture>
  <xi:include href="aarch64-core.xml"/>
</target>)xml";
        const std::string core_xml = R"xml(
<feature name="org.gnu.gdb.aarch64.core">
  <reg name="x0" bitsize="64"/>
  <reg name="x29" bitsize="64" type="data_ptr" regnum="29"/>
  <reg name="x30" bitsize="64" type="code_ptr" regnum="30"/>
  <reg name="sp" bitsize="64" type="data_ptr" regnum="31"/>
  <reg name="pc" bitsize="64" type="code_ptr" regnum="32"/>
  <reg name="cpsr" bitsize="32" regnum="33"/>
</feature>)xml";
        auto desc = parse_rsp_target_xml(root_xml, [&](std::string_view href) -> Result<std::string> {
            if (href == "aarch64-core.xml") {
                return core_xml;
            }
            return make_error("unexpected annex");
        });
        ASSERT_TRUE(desc.has_value()) << desc.error().message;
        EXPECT_EQ(desc->architecture, Architecture::ARM64);
        EXPECT_EQ(desc->endianness, Endianness::Little);
        EXPECT_EQ(desc->address_width, AddressWidth::Bits64);

        const std::string g_buf =
            le_hex_u64(0xAA00ULL) +
            le_hex_u64(0xFFFF'0000'1000ULL) +
            le_hex_u64(0x0000'0000'400810ULL) +
            le_hex_u64(0xFFFF'0000'0FF0ULL) +
            le_hex_u64(0x0000'0000'400800ULL) +
            le_hex_u32(0x6000'0000U);
        auto regs = decode_rsp_g_packet(*desc, g_buf);
        ASSERT_TRUE(regs.has_value());
        EXPECT_EQ((*regs)[4].name, "pc");
        EXPECT_EQ((*regs)[4].value_u64, 0x400800ULL);
    }

    // 2. RISC-V 64 (riscv:rv64)
    {
        const std::string root_xml = R"xml(<?xml version="1.0"?>
<target version="1.0">
  <architecture>riscv:rv64</architecture>
  <xi:include href="riscv-64bit-cpu.xml"/>
</target>)xml";
        const std::string cpu_xml = R"xml(
<feature name="org.gnu.gdb.riscv.cpu">
  <reg name="zero" bitsize="64" regnum="0"/>
  <reg name="ra" bitsize="64" type="code_ptr" regnum="1"/>
  <reg name="sp" bitsize="64" type="data_ptr" regnum="2"/>
  <reg name="tp" bitsize="64" type="data_ptr" regnum="4"/>
  <reg name="s0" bitsize="64" type="data_ptr" regnum="8"/>
  <reg name="pc" bitsize="64" type="code_ptr" regnum="32"/>
</feature>)xml";
        auto desc = parse_rsp_target_xml(root_xml, [&](std::string_view href) -> Result<std::string> {
            if (href == "riscv-64bit-cpu.xml") {
                return cpu_xml;
            }
            return make_error("unexpected annex");
        });
        ASSERT_TRUE(desc.has_value()) << desc.error().message;
        EXPECT_EQ(desc->architecture, Architecture::RISCV64);
        EXPECT_EQ(desc->endianness, Endianness::Little);
        EXPECT_EQ(desc->address_width, AddressWidth::Bits64);
    }

    // 3. Big-endian PowerPC64
    {
        const std::string ppc_xml = R"xml(<?xml version="1.0"?>
<target version="1.0">
  <architecture>powerpc:common64</architecture>
  <endian>big</endian>
  <feature name="org.gnu.gdb.power.core">
    <reg name="r0" bitsize="64" regnum="0"/>
    <reg name="r1" bitsize="64" type="data_ptr" regnum="1"/>
    <reg name="pc" bitsize="64" type="code_ptr" regnum="64"/>
    <reg name="msr" bitsize="64" regnum="65"/>
    <reg name="lr" bitsize="64" type="code_ptr" regnum="67"/>
  </feature>
</target>)xml";
        auto desc = parse_rsp_target_xml(ppc_xml);
        ASSERT_TRUE(desc.has_value()) << desc.error().message;
        EXPECT_EQ(desc->architecture, Architecture::PowerPC64);
        EXPECT_EQ(desc->endianness, Endianness::Big);
        EXPECT_EQ(desc->address_width, AddressWidth::Bits64);

        const std::string g_buf =
            be_hex_u64(0x0102'0304'0506'0708ULL) +
            be_hex_u64(0x7FFF'0000'1000ULL) +
            be_hex_u64(0x0000'0000'1000'0400ULL) +
            be_hex_u64(0x8000'0000'0000'9032ULL) +
            be_hex_u64(0x0000'0000'1000'03FCULL);
        auto regs = decode_rsp_g_packet(*desc, g_buf);
        ASSERT_TRUE(regs.has_value());
        EXPECT_EQ((*regs)[0].value_u64, 0x0102'0304'0506'0708ULL);
        EXPECT_EQ((*regs)[2].name, "pc");
        EXPECT_EQ((*regs)[2].value_u64, 0x0000'0000'1000'0400ULL);
    }

    // 4. Big-endian MIPS32
    {
        const std::string mips_xml = R"xml(<?xml version="1.0"?>
<target version="1.0">
  <architecture>mips:isa32r2</architecture>
  <feature name="org.gnu.gdb.mips.cpu">
    <reg name="r0" bitsize="32" regnum="0"/>
    <reg name="r29" bitsize="32" type="data_ptr" regnum="29"/>
    <reg name="r31" bitsize="32" type="code_ptr" regnum="31"/>
    <reg name="status" bitsize="32" regnum="32"/>
    <reg name="pc" bitsize="32" type="code_ptr" regnum="37"/>
  </feature>
</target>)xml";
        auto desc = parse_rsp_target_xml(mips_xml);
        ASSERT_TRUE(desc.has_value()) << desc.error().message;
        EXPECT_EQ(desc->architecture, Architecture::MIPS32);
        EXPECT_EQ(desc->endianness, Endianness::Big);
        EXPECT_EQ(desc->address_width, AddressWidth::Bits32);

        const std::string g_buf =
            be_hex_u32(0u) +
            be_hex_u32(0x7FFF'E000U) +
            be_hex_u32(0x0040'0120U) +
            be_hex_u32(0x0000'FF11U) +
            be_hex_u32(0x0040'0100U);
        auto regs = decode_rsp_g_packet(*desc, g_buf);
        ASSERT_TRUE(regs.has_value());
        EXPECT_EQ((*regs)[1].category, RegisterCategory::StackPointer);
        EXPECT_EQ((*regs)[1].value_u64, 0x7FFF'E000ULL);
        EXPECT_EQ((*regs)[4].name, "pc");
        EXPECT_EQ((*regs)[4].value_u64, 0x0040'0100ULL);
    }
}

TEST(GdbRemoteRspTest, BoundedXmlParserRejectsExternalIncludeCyclesAndDtdEntities) {
    // Reject external URI in <xi:include>
    const std::string external_uri_xml = R"xml(
<target><xi:include href="http://evil.example/target.xml"/></target>)xml";
    EXPECT_FALSE(parse_rsp_target_xml(external_uri_xml, [](std::string_view) -> Result<std::string> {
        return std::string{"<feature name='x'/>"};
    }).has_value());

    // Reject path traversal in <xi:include>
    const std::string traversal_xml = R"xml(
<target><xi:include href="../etc/passwd"/></target>)xml";
    EXPECT_FALSE(parse_rsp_target_xml(traversal_xml, [](std::string_view) -> Result<std::string> {
        return std::string{"<feature name='x'/>"};
    }).has_value());

    // Reject <xi:include> cycle
    const std::string cycle_root = R"xml(<target><xi:include href="a.xml"/></target>)xml";
    auto cycle_res = parse_rsp_target_xml(cycle_root, [](std::string_view href) -> Result<std::string> {
        if (href == "a.xml") {
            return std::string{R"xml(<feature name="a"><xi:include href="b.xml"/></feature>)xml"};
        }
        return std::string{R"xml(<feature name="b"><xi:include href="a.xml"/></feature>)xml"};
    });
    EXPECT_FALSE(cycle_res.has_value());

    // Reject <!ENTITY> expansion attacks
    const std::string entity_bomb_xml = R"xml(<?xml version="1.0"?>
<!DOCTYPE target [
  <!ENTITY lol "lol">
]>
<target><architecture>&lol;</architecture></target>)xml";
    EXPECT_FALSE(parse_rsp_target_xml(entity_bomb_xml).has_value());
}

// ---------------------------------------------------------------------------
// 3. Multiprocess thread IDs (p10.20, negative sentinels, 64-bit TIDs)
// ---------------------------------------------------------------------------

TEST(GdbRemoteRspTest, MultiprocessThreadIdsNegativeSentinelsAnd64BitCollisionFreeMapping) {
    const auto sentinel_all = parse_rsp_thread_id("p-1.-1");
    ASSERT_TRUE(sentinel_all.has_value());
    EXPECT_TRUE(sentinel_all->is_negative_sentinel());
    EXPECT_FALSE(sentinel_all->is_concrete_thread());

    const auto proc_sentinel = parse_rsp_thread_id("p10.-1");
    ASSERT_TRUE(proc_sentinel.has_value());
    EXPECT_TRUE(proc_sentinel->is_negative_sentinel());
    EXPECT_FALSE(proc_sentinel->is_concrete_thread());

    auto stub = std::make_shared<StubSharedState>();
    stub->features_annexes["target.xml"] = R"xml(
<target version="1.0">
  <architecture>riscv:rv64</architecture>
  <osabi>GNU/Linux</osabi>
  <feature name="org.gnu.gdb.riscv.cpu">
    <reg name="sp" bitsize="64" type="data_ptr" regnum="2"/>
    <reg name="pc" bitsize="64" type="code_ptr" regnum="32"/>
  </feature>
</target>)xml";

    // Three colliding low-32-bit thread tokens + negative sentinel across 2 pages:
    // - p10.20  (pid 0x10, tid 0x20)
    // - p11.20  (pid 0x11, tid 0x20)
    // - p10.100000020 (pid 0x10, 64-bit tid 0x1_0000_0020)
    // - p-1.-1 (sentinel — must be filtered out of concrete thread list)
    stub->thread_info_pages = {
        "mp10.20,p-1.-1,p11.20",
        "mp10.100000020",
        "l",
    };
    stub->g_replies_by_thread["p10.20"] = le_hex_u64(0x7000ULL) + le_hex_u64(0x10000ULL);
    stub->g_replies_by_thread["p11.20"] = le_hex_u64(0x8000ULL) + le_hex_u64(0x20000ULL);
    stub->g_replies_by_thread["p10.100000020"] = le_hex_u64(0x9000ULL) + le_hex_u64(0x30000ULL);

    auto session_res = GdbRemoteBackend::open_read_only(
        std::make_unique<FakeInMemoryRspTransport>(stub));
    ASSERT_TRUE(session_res.has_value()) << session_res.error().message;
    EXPECT_EQ((*session_res)->pid(), 0x10u);

    auto threads_res = (*session_res)->threads();
    ASSERT_TRUE(threads_res.has_value());
    ASSERT_EQ(threads_res->size(), 3u);

    const ThreadId t0 = (*threads_res)[0].tid;
    const ThreadId t1 = (*threads_res)[1].tid;
    const ThreadId t2 = (*threads_res)[2].tid;
    EXPECT_NE(t0, t1);
    EXPECT_NE(t0, t2);
    EXPECT_NE(t1, t2);

    // Selecting each local ThreadId must transmit the exact multiprocess/64-bit wire token to Hg!
    EXPECT_EQ((*session_res)->thread_context(t0).instruction_pointer, 0x10000ULL);
    EXPECT_EQ((*session_res)->thread_context(t1).instruction_pointer, 0x20000ULL);
    EXPECT_EQ((*session_res)->thread_context(t2).instruction_pointer, 0x30000ULL);
}

// ---------------------------------------------------------------------------
// 4. Memory-map XML, libraries-svr4 XML, auxv PT_LOAD fallback, & strict RO audit
// ---------------------------------------------------------------------------

TEST(GdbRemoteRspTest, MemoryMapLibrariesSvr4AndStrictZeroMutationPacketAudit) {
    auto stub = std::make_shared<StubSharedState>();
    stub->features_annexes["target.xml"] = R"xml(
<target version="1.0">
  <architecture>i386:x86-64</architecture>
  <osabi>GNU/Linux</osabi>
  <feature name="org.gnu.gdb.i386.core">
    <reg name="rsp" bitsize="64" type="data_ptr" regnum="7"/>
    <reg name="rip" bitsize="64" type="code_ptr" regnum="16"/>
  </feature>
</target>)xml";

    stub->memory_map_xml = R"xml(<?xml version="1.0"?>
<!DOCTYPE memory-map PUBLIC "+//IDN gnu.org//DTD GDB Memory Map V1.0//EN" "http://sourceware.org/gdb/gdb-memory-map.dtd">
<memory-map>
  <memory type="rom" start="0x00400000" length="0x2000"/>
  <memory type="flash" start="0x08000000" length="0x10000">
    <property name="blocksize">0x1000</property>
  </memory>
  <memory type="ram" start="0x7fff0000" length="0x4000"/>
</memory-map>)xml";

    stub->libraries_svr4_xml = R"xml(<?xml version="1.0"?>
<library-list-svr4 version="1.0" main-lm="0x7ffff7ffe190">
  <library name="/usr/bin/target_app" lm="0x7ffff7ffe190" l_addr="0x00400000" l_ld="0x00403e00"/>
  <library name="/lib/x86_64-linux-gnu/libc.so.6" lm="0x7ffff7ffd000" l_addr="0x7ffff7c00000" l_ld="0x7ffff7d90000"/>
</library-list-svr4>)xml";

    stub->thread_info_pages = {"mp2a.2a", "l"};
    stub->halt_reply = "T05thread:p2a.2a;";
    stub->default_g_reply = le_hex_u64(0x7fff'2000ULL) + le_hex_u64(0x0040'1080ULL);

    // Populate a 64-byte ELF64 header at 0x00400000 with e_entry = 0x00401080
    std::vector<std::uint8_t> elf_hdr(64u, 0u);
    elf_hdr[0] = 0x7Fu;
    elf_hdr[1] = 'E';
    elf_hdr[2] = 'L';
    elf_hdr[3] = 'F';
    elf_hdr[4] = 2u;  // ELFCLASS64
    elf_hdr[5] = 1u;  // ELFDATA2LSB
    const std::uint64_t entry = 0x0040'1080ULL;
    std::memcpy(elf_hdr.data() + 24u, &entry, sizeof(entry));
    stub->memory_segments[0x0040'0000ULL] = elf_hdr;

    {
        auto session_res = GdbRemoteBackend::open_read_only(
            std::make_unique<FakeInMemoryRspTransport>(stub));
        ASSERT_TRUE(session_res.has_value()) << session_res.error().message;
        IProcessSession& session = **session_res;

        EXPECT_TRUE(session.is_read_only());
        EXPECT_FALSE(session.is_crash_dump());
        EXPECT_EQ(session.info().name, "target_app");

        auto regions = session.memory_regions();
        ASSERT_TRUE(regions.has_value()) << regions.error().message;
        ASSERT_EQ(regions->size(), 3u);
        EXPECT_EQ((*regions)[0].start_address, 0x0040'0000ULL);
        EXPECT_FALSE((*regions)[0].protection.writable);
        EXPECT_TRUE((*regions)[0].protection.readable);
        EXPECT_EQ((*regions)[1].start_address, 0x0800'0000ULL);
        EXPECT_FALSE((*regions)[1].protection.writable);
        EXPECT_EQ((*regions)[2].start_address, 0x7fff'0000ULL);
        EXPECT_TRUE((*regions)[2].protection.writable);

        auto mods = session.modules();
        ASSERT_TRUE(mods.has_value()) << mods.error().message;
        ASSERT_EQ(mods->size(), 2u);
        EXPECT_TRUE((*mods)[0].is_main_module);
        EXPECT_EQ((*mods)[0].name, "target_app");
        EXPECT_EQ((*mods)[0].entry_point, 0x0040'1080ULL);
        EXPECT_EQ((*mods)[1].name, "libc.so.6");

        std::array<std::uint8_t, 4> magic{};
        auto n = session.read_memory(0x0040'0000ULL, magic);
        ASSERT_TRUE(n.has_value());
        EXPECT_EQ(*n, 4u);
        EXPECT_EQ(magic[0], 0x7Fu);
        EXPECT_EQ(magic[1], 'E');

        // Attempt every mutating operation on IProcessSession — ALL must fail closed!
        const std::array<std::uint8_t, 4> patch{0x90u, 0x90u, 0x90u, 0x90u};
        EXPECT_FALSE(session.write_memory(0x0040'0000ULL, patch).has_value());
        EXPECT_FALSE(session.suspend().has_value());
        EXPECT_FALSE(session.resume().has_value());
        EXPECT_FALSE(session.suspend_thread(0x2Au).has_value());
        EXPECT_FALSE(session.resume_thread(0x2Au).has_value());

        // Snapshot & internals integration must also emit zero mutating packets
        const ProcessStateSnapshot snap = capture_process_snapshot(session);
        EXPECT_EQ(snap.target_id.backend, BackendKind::GdbRemote);
        EXPECT_EQ(snap.regions.availability, CaptureAvailability::Complete);
        EXPECT_EQ(snap.handles.availability, CaptureAvailability::Unavailable);
    }

    // Strict packet audit after full session lifecycle + RAII teardown:
    ASSERT_FALSE(stub->received_commands.empty());
    for (const std::string& cmd : stub->received_commands) {
        EXPECT_FALSE(is_mutating_rsp_packet(cmd))
            << "Forbidden mutating RSP packet transmitted: " << cmd;
        EXPECT_FALSE(cmd.starts_with("M"));
        EXPECT_FALSE(cmd.starts_with("X"));
        EXPECT_FALSE(cmd.starts_with("G"));
        EXPECT_FALSE(cmd.starts_with("P"));
        EXPECT_FALSE(cmd.starts_with("Z"));
        EXPECT_FALSE(cmd.starts_with("z"));
        EXPECT_FALSE(cmd.starts_with("vKill"));
    }

    // Direct RspClient wire-level read-only guard check:
    auto guard_stub = std::make_shared<StubSharedState>();
    RspClientOptions guard_opts{};
    guard_opts.strict_read_only = true;
    RspClient guarded_client(std::make_unique<FakeInMemoryRspTransport>(guard_stub), guard_opts);
    for (const std::string_view forbidden : {
             "M400000,4:90909090",
             "X400000,0:",
             "G0000000000000000",
             "P0=0000000000000000",
             "Z0,401000,1",
             "z0,401000,1",
             "vKill;2a",
             "k",
             "vCont;c",
             "c",
             "s",
         }) {
        EXPECT_FALSE(guarded_client.send_command(forbidden).has_value()) << forbidden;
    }
    EXPECT_TRUE(guard_stub->raw_tx_wire.empty());
}

TEST(GdbRemoteRspTest, QemuUserModeAuxvPtLoadFallbackWhenMemoryMapOmitted) {
    auto stub = std::make_shared<StubSharedState>();
    stub->qsupported_reply =
        "PacketSize=400;QStartNoAckMode+;qXfer:features:read+;qXfer:auxv:read+";
    stub->features_annexes["target.xml"] = R"xml(
<target version="1.0">
  <architecture>aarch64</architecture>
  <feature name="org.gnu.gdb.aarch64.core">
    <reg name="sp" bitsize="64" type="data_ptr" regnum="31"/>
    <reg name="pc" bitsize="64" type="code_ptr" regnum="32"/>
  </feature>
</target>)xml";
    stub->thread_info_pages = {"m1", "l"};
    stub->default_g_reply = le_hex_u64(0x4000'8000ULL) + le_hex_u64(0x4000'1000ULL);

    // Build little-endian 64-bit auxv: AT_PHDR=0x40000040, AT_PHENT=56, AT_PHNUM=2, AT_PAGESZ=4096, AT_NULL
    std::string auxv;
    const auto push_auxv = [&](std::uint64_t tag, std::uint64_t val) {
        for (int i = 0; i < 8; ++i) {
            auxv.push_back(static_cast<char>((tag >> (i * 8)) & 0xFFu));
        }
        for (int i = 0; i < 8; ++i) {
            auxv.push_back(static_cast<char>((val >> (i * 8)) & 0xFFu));
        }
    };
    push_auxv(3u, 0x4000'0040ULL);
    push_auxv(4u, 56u);
    push_auxv(5u, 2u);
    push_auxv(6u, 4096u);
    push_auxv(0u, 0u);
    stub->auxv_binary = auxv;

    // Two 56-byte Elf64_Phdr entries at 0x40000040: PT_PHDR (vaddr 0x40) + PT_LOAD (RX, vaddr 0x0, memsz 0x1800)
    std::vector<std::uint8_t> phdrs(112u, 0u);
    const auto write_u32 = [&](std::size_t off, std::uint32_t v) {
        std::memcpy(phdrs.data() + off, &v, sizeof(v));
    };
    const auto write_u64 = [&](std::size_t off, std::uint64_t v) {
        std::memcpy(phdrs.data() + off, &v, sizeof(v));
    };
    // Phdr 0: PT_PHDR (6), p_vaddr = 0x40 -> bias = 0x40000040 - 0x40 = 0x40000000
    write_u32(0u, 6u);
    write_u32(4u, 4u);
    write_u64(8u, 0x40ULL);
    write_u64(16u, 0x40ULL);
    write_u64(40u, 112ULL);
    // Phdr 1: PT_LOAD (1), PF_R|PF_X (5), p_vaddr = 0x0, p_memsz = 0x1800 -> [0x40000000, 0x40002000)
    write_u32(56u + 0u, 1u);
    write_u32(56u + 4u, 5u);
    write_u64(56u + 8u, 0ULL);
    write_u64(56u + 16u, 0ULL);
    write_u64(56u + 40u, 0x1800ULL);
    stub->memory_segments[0x4000'0040ULL] = phdrs;

    auto session_res = GdbRemoteBackend::open_read_only(
        std::make_unique<FakeInMemoryRspTransport>(stub));
    ASSERT_TRUE(session_res.has_value()) << session_res.error().message;
    auto regions = (*session_res)->memory_regions();
    ASSERT_TRUE(regions.has_value());
    ASSERT_EQ(regions->size(), 1u);
    EXPECT_EQ((*regions)[0].start_address, 0x4000'0000ULL);
    EXPECT_EQ((*regions)[0].end_address, 0x4000'2000ULL);
    EXPECT_TRUE((*regions)[0].protection.readable);
    EXPECT_TRUE((*regions)[0].protection.executable);
    EXPECT_FALSE((*regions)[0].protection.writable);
}

// ---------------------------------------------------------------------------
// 5. Bare-metal QEMU graceful degradation & capability matrix honesty
// ---------------------------------------------------------------------------

TEST(GdbRemoteRspTest, BareMetalQemuGracefulDegradationAndCapabilityMatrix) {
    auto stub = std::make_shared<StubSharedState>();
    // Bare-metal QEMU system stub: no memory-map, no libraries, no auxv, no qfThreadInfo, no <osabi>
    stub->qsupported_reply = "PacketSize=1000;QStartNoAckMode+;qXfer:features:read+";
    stub->halt_reply = "S05";
    stub->features_annexes["target.xml"] = R"xml(
<target version="1.0">
  <architecture>riscv:rv64</architecture>
  <feature name="org.gnu.gdb.riscv.cpu">
    <reg name="sp" bitsize="64" type="data_ptr" regnum="2"/>
    <reg name="pc" bitsize="64" type="code_ptr" regnum="32"/>
  </feature>
</target>)xml";
    stub->default_g_reply = le_hex_u64(0x8000'4000ULL) + le_hex_u64(0x8000'0000ULL);

    auto session_res = GdbRemoteBackend::open_read_only(
        std::make_unique<FakeInMemoryRspTransport>(stub));
    ASSERT_TRUE(session_res.has_value()) << session_res.error().message;

    auto* gdb_session = dynamic_cast<IGdbRemoteSession*>(session_res->get());
    ASSERT_NE(gdb_session, nullptr);

    const TargetProfile& prof = gdb_session->target_profile();
    EXPECT_EQ(prof.backend, BackendKind::GdbRemote);
    EXPECT_EQ(prof.os, OsKind::BareMetal);
    EXPECT_EQ(prof.abi, AbiKind::Standalone);
    EXPECT_EQ(prof.architecture, Architecture::RISCV64);
    EXPECT_TRUE(gdb_session->provider_facts().remote_gdb_stub_available);

    const TargetCapabilityMatrix matrix = gdb_session->capability_matrix();
    EXPECT_EQ(matrix.get(Operation::StackUnwind).state, SupportState::SupportedValidated);
    EXPECT_EQ(matrix.get(Operation::ProcessInternals).state, SupportState::Partial);
    EXPECT_EQ(matrix.get(Operation::ProcessSnapshotDiff).state, SupportState::Partial);
    EXPECT_EQ(matrix.get(Operation::ThreadLocals).state, SupportState::Unsupported);
    EXPECT_EQ(matrix.get(Operation::RuntimeStructures).state, SupportState::Unsupported);

    // derive_target_profile(nullptr, session) also recognizes IGdbRemoteSession automatically
    const TargetProfile derived = derive_target_profile(nullptr, gdb_session);
    EXPECT_EQ(derived.backend, BackendKind::GdbRemote);
    EXPECT_EQ(derived.os, OsKind::BareMetal);

    // Memory regions, modules, and internals degrade cleanly without errors
    const auto regs = gdb_session->memory_regions();
    ASSERT_TRUE(regs.has_value());
    EXPECT_TRUE(regs->empty());

    const auto mods = gdb_session->modules();
    ASSERT_TRUE(mods.has_value());
    EXPECT_TRUE(mods->empty());

    const ProcessInternalsSnapshot internals = inspect_process_internals(*gdb_session);
    EXPECT_EQ(internals.handles.status.availability, Availability::Unavailable);
    EXPECT_EQ(internals.handles.status.source, "gdb_rsp");
    EXPECT_EQ(internals.sockets.status.availability, Availability::Unavailable);
    EXPECT_EQ(internals.security.status.availability, Availability::Unavailable);

    const ProcessStateSnapshot snap = capture_process_snapshot(*gdb_session);
    EXPECT_EQ(snap.regions.availability, CaptureAvailability::Partial);
    EXPECT_EQ(snap.handles.availability, CaptureAvailability::Unavailable);
    EXPECT_EQ(snap.launch_environment.availability, CaptureAvailability::Unavailable);
}

// ---------------------------------------------------------------------------
// 6. Endpoint trust policy & real loopback TCP socket transport test
// ---------------------------------------------------------------------------

TEST(GdbRemoteRspTest, NonLoopbackEndpointsRejectedWithoutExplicitOptIn) {
    EXPECT_TRUE(is_loopback_endpoint_host("127.0.0.1"));
    EXPECT_TRUE(is_loopback_endpoint_host("127.25.30.1"));
    EXPECT_TRUE(is_loopback_endpoint_host("::1"));
    EXPECT_TRUE(is_loopback_endpoint_host("[::1]"));
    EXPECT_TRUE(is_loopback_endpoint_host("localhost"));
    EXPECT_FALSE(is_loopback_endpoint_host("0.0.0.0"));
    EXPECT_FALSE(is_loopback_endpoint_host("::"));
    EXPECT_FALSE(is_loopback_endpoint_host("192.0.2.42"));
    EXPECT_FALSE(is_loopback_endpoint_host("2001:db8::1"));
    EXPECT_FALSE(is_loopback_endpoint_host("remote-target.internal"));

    // Must reject non-loopback IPv4, IPv6, and hostname BEFORE attempting network I/O
    auto r1 = GdbRemoteBackend::open_read_only("192.0.2.42:1234", /*allow_unencrypted=*/false);
    ASSERT_FALSE(r1.has_value());
    EXPECT_NE(r1.error().message.find("allow_unencrypted_remote_endpoint"), std::string::npos);

    auto r2 = GdbRemoteBackend::open_read_only("[2001:db8::1]:1234", /*allow_unencrypted=*/false);
    ASSERT_FALSE(r2.has_value());
    EXPECT_NE(r2.error().message.find("allow_unencrypted_remote_endpoint"), std::string::npos);

    auto r3 = GdbRemoteBackend::open_read_only("gdb.example.invalid:1234", /*allow_unencrypted=*/false);
    ASSERT_FALSE(r3.has_value());
    EXPECT_NE(r3.error().message.find("allow_unencrypted_remote_endpoint"), std::string::npos);
}

TEST(GdbRemoteRspTest, RealLoopbackTcpTransportConnectNegotiateAndReadMemory) {
#ifdef _WIN32
    WSADATA wsa{};
    ASSERT_EQ(::WSAStartup(MAKEWORD(2, 2), &wsa), 0);
    using SockType = SOCKET;
    constexpr SockType kBadSock = INVALID_SOCKET;
    const auto close_sock = [](SockType s) noexcept {
        if (s != INVALID_SOCKET) {
            ::closesocket(s);
        }
    };
#else
    using SockType = int;
    constexpr SockType kBadSock = -1;
    const auto close_sock = [](SockType s) noexcept {
        if (s >= 0) {
            ::close(s);
        }
    };
#endif

    const SockType listen_sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_NE(listen_sock, kBadSock);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    ASSERT_EQ(::bind(listen_sock, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)), 0);
    ASSERT_EQ(::listen(listen_sock, 1), 0);

    sockaddr_in bound{};
#ifdef _WIN32
    int bound_len = static_cast<int>(sizeof(bound));
#else
    socklen_t bound_len = sizeof(bound);
#endif
    ASSERT_EQ(::getsockname(listen_sock, reinterpret_cast<sockaddr*>(&bound), &bound_len), 0);
    const std::uint16_t port = ntohs(bound.sin_port);
    ASSERT_NE(port, 0u);

    auto stub = std::make_shared<StubSharedState>();
    stub->features_annexes["target.xml"] = R"xml(
<target version="1.0">
  <architecture>i386:x86-64</architecture>
  <feature name="org.gnu.gdb.i386.core">
    <reg name="rsp" bitsize="64" type="data_ptr" regnum="7"/>
    <reg name="rip" bitsize="64" type="code_ptr" regnum="16"/>
  </feature>
</target>)xml";
    stub->thread_info_pages = {"mp7.11", "l"};
    stub->halt_reply = "T05thread:p7.11;";
    stub->g_replies_by_thread["p7.11"] = le_hex_u64(0x7fff'8800ULL) + le_hex_u64(0x0040'2000ULL);
    stub->memory_segments[0x0040'2000ULL] = {0x55u, 0x48u, 0x89u, 0xE5u};

    std::thread server_thread([listen_sock, stub, close_sock]() {
        const SockType client_sock = ::accept(listen_sock, nullptr, nullptr);
        close_sock(listen_sock);
        if (client_sock == kBadSock) {
            return;
        }
        std::array<std::uint8_t, 512> rx{};
        for (;;) {
#ifdef _WIN32
            const int n = ::recv(client_sock, reinterpret_cast<char*>(rx.data()),
                                 static_cast<int>(rx.size()), 0);
#else
            const ssize_t n = ::recv(client_sock, rx.data(), rx.size(), 0);
#endif
            if (n <= 0) {
                break;
            }
            stub->process_incoming_bytes(
                std::span<const std::uint8_t>(rx.data(), static_cast<std::size_t>(n)));
            while (!stub->tx_to_client.empty()) {
                std::vector<std::uint8_t> out(
                    stub->tx_to_client.begin(), stub->tx_to_client.end());
                stub->tx_to_client.clear();
#ifdef _WIN32
                (void)::send(client_sock, reinterpret_cast<const char*>(out.data()),
                             static_cast<int>(out.size()), 0);
#else
                (void)::send(client_sock, out.data(), out.size(), 0);
#endif
            }
        }
        close_sock(client_sock);
    });

    {
        RemoteEndpointOptions ep{};
        ep.host = "127.0.0.1";
        ep.port = port;
        ep.allow_unencrypted_remote_endpoint = false;

        auto session_res = GdbRemoteBackend::open_read_only(ep);
        ASSERT_TRUE(session_res.has_value()) << session_res.error().message;

        std::array<std::uint8_t, 4> prologue{};
        auto read_res = (*session_res)->read_memory(0x0040'2000ULL, prologue);
        ASSERT_TRUE(read_res.has_value()) << read_res.error().message;
        EXPECT_EQ(*read_res, 4u);
        EXPECT_EQ(prologue[0], 0x55u);
        EXPECT_EQ(prologue[3], 0xE5u);

        const ThreadContext ctx = (*session_res)->thread_context(0x11u);
        EXPECT_EQ(ctx.instruction_pointer, 0x0040'2000ULL);
    }

    server_thread.join();
}

}  // namespace
}  // namespace peelf
