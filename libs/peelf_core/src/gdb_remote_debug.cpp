#include <peelf/gdb_remote.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace peelf {

namespace {

[[nodiscard]] constexpr std::string_view trim_ascii(std::string_view sv) noexcept {
    while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t' ||
                           sv.front() == '\r' || sv.front() == '\n')) {
        sv.remove_prefix(1u);
    }
    while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t' ||
                           sv.back() == '\r' || sv.back() == '\n')) {
        sv.remove_suffix(1u);
    }
    return sv;
}

[[nodiscard]] constexpr std::optional<std::uint8_t> hex_nibble(char ch) noexcept {
    if (ch >= '0' && ch <= '9') {
        return static_cast<std::uint8_t>(ch - '0');
    }
    if (ch >= 'a' && ch <= 'f') {
        return static_cast<std::uint8_t>(10 + (ch - 'a'));
    }
    if (ch >= 'A' && ch <= 'F') {
        return static_cast<std::uint8_t>(10 + (ch - 'A'));
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::uint64_t> parse_uint64_hex(std::string_view sv) noexcept {
    sv = trim_ascii(sv);
    if (sv.starts_with("0x") || sv.starts_with("0X")) {
        sv.remove_prefix(2u);
    }
    if (sv.empty() || sv.size() > 16u) {
        return std::nullopt;
    }
    std::uint64_t val = 0u;
    for (const char ch : sv) {
        const auto nib = hex_nibble(ch);
        if (!nib.has_value()) {
            return std::nullopt;
        }
        val = (val << 4u) | static_cast<std::uint64_t>(*nib);
    }
    return val;
}

[[nodiscard]] std::string format_hex_u64(std::uint64_t val) {
    static constexpr std::string_view kHex = "0123456789abcdef";
    if (val == 0u) {
        return "0";
    }
    std::array<char, 16> buf{};
    std::size_t pos = buf.size();
    while (val != 0u && pos > 0u) {
        --pos;
        buf[pos] = kHex[static_cast<std::size_t>(val & 0xFu)];
        val >>= 4u;
    }
    return std::string(buf.data() + pos, buf.size() - pos);
}

[[nodiscard]] std::string encode_bytes_hex(std::span<const std::uint8_t> bytes) {
    static constexpr std::string_view kHex = "0123456789abcdef";
    std::string out;
    out.resize(bytes.size() * 2u);
    for (std::size_t i = 0u; i < bytes.size(); ++i) {
        out[i * 2u] = kHex[static_cast<std::size_t>((bytes[i] >> 4u) & 0xFu)];
        out[i * 2u + 1u] = kHex[static_cast<std::size_t>(bytes[i] & 0xFu)];
    }
    return out;
}

[[nodiscard]] std::optional<std::string> decode_hex_ascii(std::string_view hex) {
    if ((hex.size() % 2u) != 0u) {
        return std::nullopt;
    }
    std::string out;
    out.resize(hex.size() / 2u);
    for (std::size_t i = 0u; i < out.size(); ++i) {
        const auto hi = hex_nibble(hex[i * 2u]);
        const auto lo = hex_nibble(hex[i * 2u + 1u]);
        if (!hi.has_value() || !lo.has_value()) {
            return std::nullopt;
        }
        out[i] = static_cast<char>((*hi << 4u) | *lo);
    }
    return out;
}

[[nodiscard]] constexpr bool is_rsp_error_reply(std::string_view reply) noexcept {
    if (reply.size() == 3u && reply.front() == 'E') {
        return hex_nibble(reply[1]).has_value() && hex_nibble(reply[2]).has_value();
    }
    return reply.starts_with("E.");
}

[[nodiscard]] constexpr bool ascii_iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0u; i < a.size(); ++i) {
        const auto ca = static_cast<unsigned char>(a[i]);
        const auto cb = static_cast<unsigned char>(b[i]);
        if (std::tolower(ca) != std::tolower(cb)) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] RspTargetDescription synthesize_debug_fallback_target_description(
    Architecture arch,
    Endianness endian,
    AddressWidth width) {
    RspTargetDescription desc{};
    desc.architecture = arch;
    desc.endianness = endian;
    desc.address_width = width;
    desc.explicit_endianness = true;

    const auto add_reg = [&](std::string name,
                             std::uint32_t regnum,
                             std::uint32_t bitsize,
                             RegisterCategory cat) {
        desc.registers.push_back(RspRegisterSpec{
            .name = std::move(name),
            .regnum = regnum,
            .bitsize = bitsize,
            .type = "int",
            .group = "general",
            .feature_name = "fallback",
            .category = cat,
            .save_restore = true,
        });
    };

    switch (arch) {
        case Architecture::X86_64: {
            static constexpr std::array<std::string_view, 16> kGprs = {
                "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};
            for (std::uint32_t i = 0u; i < kGprs.size(); ++i) {
                RegisterCategory cat = RegisterCategory::General;
                if (kGprs[i] == "rsp") {
                    cat = RegisterCategory::StackPointer;
                } else if (kGprs[i] == "rbp") {
                    cat = RegisterCategory::FramePointer;
                }
                add_reg(std::string(kGprs[i]), i, 64u, cat);
            }
            add_reg("rip", 16u, 64u, RegisterCategory::InstructionPointer);
            add_reg("eflags", 17u, 32u, RegisterCategory::Flags);
            break;
        }
        case Architecture::X86: {
            static constexpr std::array<std::string_view, 8> kGprs = {
                "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
            for (std::uint32_t i = 0u; i < kGprs.size(); ++i) {
                RegisterCategory cat = RegisterCategory::General;
                if (kGprs[i] == "esp") {
                    cat = RegisterCategory::StackPointer;
                } else if (kGprs[i] == "ebp") {
                    cat = RegisterCategory::FramePointer;
                }
                add_reg(std::string(kGprs[i]), i, 32u, cat);
            }
            add_reg("eip", 8u, 32u, RegisterCategory::InstructionPointer);
            add_reg("eflags", 9u, 32u, RegisterCategory::Flags);
            break;
        }
        case Architecture::ARM64: {
            for (std::uint32_t i = 0u; i < 31u; ++i) {
                const RegisterCategory cat =
                    (i == 29u) ? RegisterCategory::FramePointer : RegisterCategory::General;
                add_reg("x" + std::to_string(i), i, 64u, cat);
            }
            add_reg("sp", 31u, 64u, RegisterCategory::StackPointer);
            add_reg("pc", 32u, 64u, RegisterCategory::InstructionPointer);
            add_reg("cpsr", 33u, 32u, RegisterCategory::Flags);
            break;
        }
        case Architecture::ARM: {
            for (std::uint32_t i = 0u; i < 13u; ++i) {
                const RegisterCategory cat =
                    (i == 11u) ? RegisterCategory::FramePointer : RegisterCategory::General;
                add_reg("r" + std::to_string(i), i, 32u, cat);
            }
            add_reg("sp", 13u, 32u, RegisterCategory::StackPointer);
            add_reg("lr", 14u, 32u, RegisterCategory::General);
            add_reg("pc", 15u, 32u, RegisterCategory::InstructionPointer);
            add_reg("cpsr", 25u, 32u, RegisterCategory::Flags);
            break;
        }
        case Architecture::RISCV64:
        case Architecture::RISCV32: {
            const std::uint32_t bits = (arch == Architecture::RISCV64) ? 64u : 32u;
            for (std::uint32_t i = 0u; i < 32u; ++i) {
                RegisterCategory cat = RegisterCategory::General;
                if (i == 2u) {
                    cat = RegisterCategory::StackPointer;
                } else if (i == 8u) {
                    cat = RegisterCategory::FramePointer;
                } else if (i == 4u) {
                    cat = RegisterCategory::SegmentOrTls;
                }
                add_reg("x" + std::to_string(i), i, bits, cat);
            }
            add_reg("pc", 32u, bits, RegisterCategory::InstructionPointer);
            break;
        }
        case Architecture::PowerPC64:
        case Architecture::PowerPC: {
            const std::uint32_t bits = (arch == Architecture::PowerPC64) ? 64u : 32u;
            for (std::uint32_t i = 0u; i < 32u; ++i) {
                const RegisterCategory cat =
                    (i == 1u) ? RegisterCategory::StackPointer : RegisterCategory::General;
                add_reg("r" + std::to_string(i), i, bits, cat);
            }
            add_reg("pc", 64u, bits, RegisterCategory::InstructionPointer);
            add_reg("msr", 65u, bits, RegisterCategory::Flags);
            add_reg("cr", 66u, 32u, RegisterCategory::Flags);
            add_reg("lr", 67u, bits, RegisterCategory::General);
            add_reg("ctr", 68u, bits, RegisterCategory::General);
            break;
        }
        case Architecture::MIPS64:
        case Architecture::MIPS32: {
            const std::uint32_t bits = (arch == Architecture::MIPS64) ? 64u : 32u;
            for (std::uint32_t i = 0u; i < 32u; ++i) {
                RegisterCategory cat = RegisterCategory::General;
                if (i == 29u) {
                    cat = RegisterCategory::StackPointer;
                } else if (i == 30u) {
                    cat = RegisterCategory::FramePointer;
                }
                add_reg("r" + std::to_string(i), i, bits, cat);
            }
            add_reg("pc", 37u, bits, RegisterCategory::InstructionPointer);
            break;
        }
        case Architecture::Unknown:
            break;
    }

    return desc;
}

void decode_debug_architectural_flags(
    Architecture arch,
    const RspTargetDescription& desc,
    std::uint64_t flags_val,
    std::vector<FlagBitInfo>& out_flags) {
    if (!desc.flags_types.empty() && !desc.flags_types.front().fields.empty()) {
        for (const auto& f : desc.flags_types.front().fields) {
            if (f.start_bit == f.end_bit && f.start_bit < 64u) {
                out_flags.push_back(FlagBitInfo{
                    .name = f.name,
                    .bit = f.start_bit,
                    .set = ((flags_val >> f.start_bit) & 1ULL) != 0ULL,
                    .description = f.name,
                });
            }
        }
        if (!out_flags.empty()) {
            return;
        }
    }

    if (arch == Architecture::X86 || arch == Architecture::X86_64) {
        struct BitSpec {
            const char* name;
            std::uint8_t bit;
            const char* desc;
        };
        static constexpr std::array<BitSpec, 9> kX86Flags = {{
            {"CF", 0u, "Carry Flag"},
            {"PF", 2u, "Parity Flag"},
            {"AF", 4u, "Auxiliary Carry Flag"},
            {"ZF", 6u, "Zero Flag"},
            {"SF", 7u, "Sign Flag"},
            {"TF", 8u, "Trap Flag"},
            {"IF", 9u, "Interrupt Enable Flag"},
            {"DF", 10u, "Direction Flag"},
            {"OF", 11u, "Overflow Flag"},
        }};
        for (const auto& b : kX86Flags) {
            out_flags.push_back(FlagBitInfo{
                .name = b.name,
                .bit = b.bit,
                .set = ((flags_val >> b.bit) & 1ULL) != 0ULL,
                .description = b.desc,
            });
        }
    } else if (arch == Architecture::ARM || arch == Architecture::ARM64) {
        struct BitSpec {
            const char* name;
            std::uint8_t bit;
            const char* desc;
        };
        static constexpr std::array<BitSpec, 4> kArmFlags = {{
            {"N", 31u, "Negative Condition Flag"},
            {"Z", 30u, "Zero Condition Flag"},
            {"C", 29u, "Carry Condition Flag"},
            {"V", 28u, "Overflow Condition Flag"},
        }};
        for (const auto& b : kArmFlags) {
            out_flags.push_back(FlagBitInfo{
                .name = b.name,
                .bit = b.bit,
                .set = ((flags_val >> b.bit) & 1ULL) != 0ULL,
                .description = b.desc,
            });
        }
    }
}

[[nodiscard]] MemoryProtection parse_debug_memory_map_protection(const RspMemoryMapEntry& entry) {
    if (!entry.permissions.empty()) {
        MemoryProtection prot{};
        for (const char ch : entry.permissions) {
            if (ch == 'r' || ch == 'R') {
                prot.readable = true;
            } else if (ch == 'w' || ch == 'W') {
                prot.writable = true;
            } else if (ch == 'x' || ch == 'X') {
                prot.executable = true;
            }
        }
        return prot;
    }

    switch (entry.type) {
        case RspMemoryRegionType::Ram:
            return MemoryProtection{.readable = true, .writable = true, .executable = true};
        case RspMemoryRegionType::Rom:
        case RspMemoryRegionType::Flash:
            return MemoryProtection{.readable = true, .writable = false, .executable = true};
        case RspMemoryRegionType::Unknown:
            return MemoryProtection{.readable = true, .writable = false, .executable = false};
    }
    return MemoryProtection{.readable = true, .writable = false, .executable = false};
}

[[nodiscard]] bool matches_register_alias(
    Architecture arch,
    std::string_view spec_name,
    std::string_view query_name) noexcept {
    if (ascii_iequals(spec_name, query_name)) {
        return true;
    }

    const auto pair_eq = [&](std::string_view a, std::string_view b) noexcept {
        return (ascii_iequals(spec_name, a) && ascii_iequals(query_name, b)) ||
               (ascii_iequals(spec_name, b) && ascii_iequals(query_name, a));
    };

    if (arch == Architecture::X86_64) {
        return pair_eq("eflags", "rflags");
    }
    if (arch == Architecture::ARM64) {
        return pair_eq("x29", "fp") || pair_eq("x30", "lr") || pair_eq("cpsr", "pstate");
    }
    if (arch == Architecture::ARM) {
        return pair_eq("r11", "fp") || pair_eq("r12", "ip") ||
               pair_eq("r13", "sp") || pair_eq("r14", "lr") || pair_eq("r15", "pc");
    }
    if (arch == Architecture::RISCV32 || arch == Architecture::RISCV64) {
        return pair_eq("x0", "zero") || pair_eq("x1", "ra") || pair_eq("x2", "sp") ||
               pair_eq("x3", "gp") || pair_eq("x4", "tp") || pair_eq("x8", "fp") ||
               pair_eq("x8", "s0") || pair_eq("x10", "a0") || pair_eq("x11", "a1");
    }
    if (arch == Architecture::PowerPC || arch == Architecture::PowerPC64) {
        return pair_eq("pc", "nip") || pair_eq("pc", "nia");
    }
    if (arch == Architecture::MIPS32 || arch == Architecture::MIPS64) {
        return pair_eq("r29", "sp") || pair_eq("r30", "fp") || pair_eq("r31", "ra");
    }
    return false;
}

[[nodiscard]] bool is_link_register_spec(Architecture arch, const RspRegisterSpec& spec) noexcept {
    if (ascii_iequals(spec.name, "lr") || ascii_iequals(spec.name, "x30") ||
        ascii_iequals(spec.name, "ra") || ascii_iequals(spec.name, "r31") ||
        spec.name == "$31") {
        return true;
    }
    if ((arch == Architecture::RISCV32 || arch == Architecture::RISCV64) &&
        ascii_iequals(spec.name, "x1")) {
        return true;
    }
    if (arch == Architecture::ARM && ascii_iequals(spec.name, "r14")) {
        return true;
    }
    return false;
}

struct ParsedStopReply {
    enum class Kind : std::uint8_t {
        SignalStop,   ///< `Sxx` or `Txx...`
        ProcessExit,  ///< `Wxx`
        SignalTerm,   ///< `Xxx`
    };

    Kind kind{Kind::SignalStop};
    std::uint8_t signal_or_exit{0};
    std::optional<RspRemoteThreadId> thread{};
    std::optional<std::uint64_t> watch_address{};
    std::string watch_kind{};  ///< `"watch"`, `"rwatch"`, `"awatch"`
    bool swbreak{false};
    bool hwbreak{false};
    std::unordered_map<std::uint32_t, std::string> inline_register_hex{};
};

[[nodiscard]] Result<ParsedStopReply> parse_rsp_stop_reply_packet(std::string_view raw) {
    const std::string_view pkt = trim_ascii(raw);
    if (pkt.size() < 3u) {
        return make_error("Malformed or truncated GDB RSP stop-reply packet '" +
                          std::string(pkt) + "'");
    }

    const char lead = pkt.front();
    if (lead != 'S' && lead != 'T' && lead != 'W' && lead != 'X') {
        return make_error("Unexpected GDB RSP stop-reply packet '" + std::string(pkt) + "'");
    }

    std::size_t code_end = 1u;
    while (code_end < pkt.size() && code_end < 3u && hex_nibble(pkt[code_end]).has_value()) {
        ++code_end;
    }
    if (code_end <= 1u) {
        return make_error("Invalid hex code in GDB RSP stop-reply '" + std::string(pkt) + "'");
    }
    const auto code_val = parse_uint64_hex(pkt.substr(1u, code_end - 1u));
    if (!code_val.has_value()) {
        return make_error("Failed to parse GDB RSP stop-reply status byte");
    }

    ParsedStopReply out{};
    out.signal_or_exit = static_cast<std::uint8_t>(*code_val & 0xFFu);

    if (lead == 'W') {
        out.kind = ParsedStopReply::Kind::ProcessExit;
        return out;
    }
    if (lead == 'X') {
        out.kind = ParsedStopReply::Kind::SignalTerm;
        return out;
    }

    out.kind = ParsedStopReply::Kind::SignalStop;
    if (lead == 'S') {
        return out;
    }

    // Parse `Txx<key>:<val>;...`
    std::size_t pos = code_end;
    while (pos < pkt.size()) {
        const std::size_t semi = pkt.find(';', pos);
        const std::string_view kv =
            (semi == std::string_view::npos) ? pkt.substr(pos) : pkt.substr(pos, semi - pos);
        pos = (semi == std::string_view::npos) ? pkt.size() : (semi + 1u);

        if (kv.empty()) {
            continue;
        }
        const std::size_t colon = kv.find(':');
        if (colon == std::string_view::npos) {
            continue;
        }
        const std::string_view key = trim_ascii(kv.substr(0u, colon));
        const std::string_view val = trim_ascii(kv.substr(colon + 1u));
        if (key.empty()) {
            continue;
        }

        if (key == "thread") {
            if (auto parsed_tid = parse_rsp_thread_id(val);
                parsed_tid.has_value() && parsed_tid->is_concrete_thread()) {
                out.thread = std::move(*parsed_tid);
            }
        } else if (key == "watch" || key == "rwatch" || key == "awatch") {
            if (const auto addr = parse_uint64_hex(val); addr.has_value()) {
                out.watch_address = *addr;
                out.watch_kind = std::string(key);
            }
        } else if (key == "swbreak") {
            out.swbreak = true;
        } else if (key == "hwbreak") {
            out.hwbreak = true;
        } else if (const auto regnum = parse_uint64_hex(key);
                   regnum.has_value() && *regnum <= 0xFFFF'FFFFULL && !val.empty()) {
            out.inline_register_hex[static_cast<std::uint32_t>(*regnum)] = std::string(val);
        }
    }

    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// RspClient WU-25b methods
// ---------------------------------------------------------------------------

Result<std::size_t> RspClient::write_memory(
    std::uint64_t address,
    std::span<const std::uint8_t> data,
    std::stop_token stop_token) {
    if (options_.strict_read_only) {
        return make_error(
            "Refusing to transmit GDB RSP memory write ('M') in strictly read-only mode");
    }
    if (transport_ == nullptr || !transport_->is_open()) {
        return make_error("GDB RSP transport is not connected");
    }
    if (data.empty()) {
        return std::size_t{0u};
    }

    const std::size_t effective_pkt =
        std::max<std::size_t>(64u, std::min(capabilities_.packet_size, options_.max_packet_size));
    const std::size_t max_chunk_bytes = std::max<std::size_t>(16u, (effective_pkt - 40u) / 2u);

    std::size_t total_written = 0u;
    while (total_written < data.size()) {
        const auto chunk_addr =
            checked_add_u64(address, static_cast<std::uint64_t>(total_written));
        if (!chunk_addr.has_value()) {
            return make_error("GDB RSP memory write address overflow");
        }

        const std::size_t chunk_len = std::min(data.size() - total_written, max_chunk_bytes);
        const std::string hex_payload = encode_bytes_hex(data.subspan(total_written, chunk_len));
        const std::string cmd = "M" + format_hex_u64(*chunk_addr) + "," +
                                format_hex_u64(chunk_len) + ":" + hex_payload;

        auto reply = send_command(cmd, stop_token);
        if (!reply) {
            return std::unexpected(reply.error());
        }
        const std::string_view trimmed = trim_ascii(*reply);
        if (trimmed != "OK") {
            if (trimmed.empty()) {
                return make_error("GDB RSP stub does not support 'M' memory write packets");
            }
            return make_error("GDB RSP memory write failed at 0x" + format_hex_u64(*chunk_addr) +
                              " with '" + std::string(trimmed) + "'");
        }
        total_written += chunk_len;
    }

    return total_written;
}

Result<RspVContCapabilities> RspClient::negotiate_vcont(std::stop_token stop_token) {
    auto reply = send_command("vCont?", stop_token);
    if (!reply) {
        return std::unexpected(reply.error());
    }

    RspVContCapabilities caps{};
    caps.probed = true;
    const std::string_view sv = trim_ascii(*reply);
    if (sv.empty() || !sv.starts_with("vCont")) {
        caps.supported = false;
        return caps;
    }

    std::size_t pos = 5u;
    while (pos < sv.size()) {
        if (sv[pos] == ';') {
            ++pos;
        }
        const std::size_t next_semi = sv.find(';', pos);
        const std::string_view tok = trim_ascii(
            next_semi == std::string_view::npos ? sv.substr(pos) : sv.substr(pos, next_semi - pos));
        pos = (next_semi == std::string_view::npos) ? sv.size() : next_semi;

        if (tok.empty()) {
            continue;
        }
        switch (tok.front()) {
            case 'c':
                caps.cont = true;
                caps.supported = true;
                break;
            case 'C':
                caps.cont_signal = true;
                caps.supported = true;
                break;
            case 's':
                caps.step = true;
                caps.supported = true;
                break;
            case 'S':
                caps.step_signal = true;
                caps.supported = true;
                break;
            case 't':
                caps.stop = true;
                caps.supported = true;
                break;
            case 'r':
                caps.range_step = true;
                caps.supported = true;
                break;
            default:
                break;
        }
    }

    return caps;
}

Result<void> RspClient::send_command_no_reply(
    std::string_view payload,
    std::stop_token stop_token) {
    if (options_.strict_read_only && is_mutating_rsp_packet(payload)) {
        return make_error(
            "Refusing to transmit mutating GDB RSP command in strictly read-only session");
    }
    if (transport_ == nullptr || !transport_->is_open()) {
        return make_error("GDB RSP transport is not connected");
    }

    selected_hg_thread_.clear();
    const std::string frame = rsp_encode_frame(payload);
    const std::span<const std::uint8_t> frame_bytes(
        reinterpret_cast<const std::uint8_t*>(frame.data()), frame.size());

    if (no_ack_mode_) {
        return transport_->write_all(frame_bytes, options_.command_timeout, stop_token);
    }

    const std::size_t max_tx_attempts = options_.max_retries + 1u;
    for (std::size_t attempt = 0u; attempt < max_tx_attempts; ++attempt) {
        if (auto w = transport_->write_all(frame_bytes, options_.command_timeout, stop_token); !w) {
            return std::unexpected(w.error());
        }

        std::size_t noise = 0u;
        for (;;) {
            auto b = read_byte(options_.command_timeout, stop_token);
            if (!b) {
                return std::unexpected(b.error());
            }
            if (*b == static_cast<std::uint8_t>('+')) {
                return {};
            }
            if (*b == static_cast<std::uint8_t>('-')) {
                break;
            }
            if (*b == static_cast<std::uint8_t>('$')) {
                // Minimal stub skipped '+' and immediately began emitting the stop-reply frame.
                if (rx_offset_ > 0u && rx_buffer_[rx_offset_ - 1u] == static_cast<std::uint8_t>('$')) {
                    --rx_offset_;
                } else {
                    rx_buffer_.insert(
                        rx_buffer_.begin() + static_cast<std::ptrdiff_t>(rx_offset_),
                        static_cast<std::uint8_t>('$'));
                }
                return {};
            }
            ++noise;
            if (noise > 256u) {
                return make_error("Expected '+' or '-' ACK/NAK from GDB RSP stub");
            }
        }
    }

    return make_error("GDB RSP resume command rejected with repeated '-' NAKs from stub");
}

Result<void> RspClient::send_interrupt(std::stop_token stop_token) {
    if (options_.strict_read_only) {
        return make_error("Refusing to transmit 0x03 interrupt in strictly read-only RSP mode");
    }
    if (transport_ == nullptr || !transport_->is_open()) {
        return make_error("GDB RSP transport is not connected");
    }
    const std::array<std::uint8_t, 1> ctrl_c{0x03u};
    return transport_->write_all(ctrl_c, options_.command_timeout, stop_token);
}

Result<std::optional<std::string>> RspClient::try_receive_packet(
    std::chrono::milliseconds timeout,
    std::stop_token stop_token) {
    if (transport_ == nullptr || !transport_->is_open()) {
        return make_error("GDB RSP transport is not connected");
    }

    const auto clamped_timeout = std::max(timeout, std::chrono::milliseconds{0});
    const auto deadline = std::chrono::steady_clock::now() + clamped_timeout;

    for (;;) {
        while (rx_offset_ < rx_buffer_.size()) {
            if (rx_buffer_[rx_offset_] == static_cast<std::uint8_t>('$')) {
                auto pkt = receive_packet_with_nak_retries(stop_token);
                if (!pkt) {
                    return std::unexpected(pkt.error());
                }
                return std::optional<std::string>{std::move(*pkt)};
            }
            ++rx_offset_;
        }
        rx_buffer_.clear();
        rx_offset_ = 0u;

        const auto now = std::chrono::steady_clock::now();
        const auto rem =
            (now < deadline)
                ? std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now)
                : std::chrono::milliseconds{0};

        std::array<std::uint8_t, 4096> temp{};
        auto outcome = transport_->read_some(temp, rem, stop_token);
        if (!outcome) {
            return std::unexpected(outcome.error());
        }
        if (outcome->status == RspIoStatus::Timeout) {
            return std::optional<std::string>{std::nullopt};
        }
        if (outcome->status == RspIoStatus::Cancelled) {
            return make_error("GDB RSP stop-reply wait cancelled");
        }
        if (outcome->status == RspIoStatus::EndOfStream) {
            return make_error("GDB RSP transport closed by remote stub");
        }
        if (outcome->bytes_read == 0u) {
            if (std::chrono::steady_clock::now() >= deadline) {
                return std::optional<std::string>{std::nullopt};
            }
            continue;
        }

        rx_buffer_.insert(
            rx_buffer_.end(),
            temp.begin(),
            temp.begin() + static_cast<std::ptrdiff_t>(outcome->bytes_read));
    }
}

// ---------------------------------------------------------------------------
// Opt-in GdbRemoteDebugSession (IDebugSession + shadow-filtered IGdbRemoteSession)
// ---------------------------------------------------------------------------

namespace {

enum class StubPacketSupport : std::uint8_t {
    Unprobed = 0,
    Supported,
    Unsupported,
};

struct RemoteBreakpointEntry {
    debugger::BreakpointDescriptor desc{};
    std::uint8_t z_type{0};               ///< `0`=`Z0`, `1`=`Z1`, `2`=`Z2`, `3`=`Z3`, `4`=`Z4`
    std::uint32_t z_kind{1};              ///< Size/kind token passed to `Z<type>,<addr>,<kind>`
    bool used_client_memory_trap{false};  ///< True iff `Z0` replied `""` and `M` trap write succeeded
};

struct TempStepBreakpoint {
    bool active{false};
    bool armed_own_trap{false};
    bool used_client_memory_trap{false};
    std::uint64_t address{0};
    std::uint32_t z_kind{1};
    std::vector<std::uint8_t> original_bytes{};
};

class GdbRemoteDebugSession final : public IGdbRemoteDebugSession {
public:
    explicit GdbRemoteDebugSession(RspClient client)
        : client_(std::move(client))
        , remote_view_(*this) {
        client_.set_read_only_mode(false);
    }

    GdbRemoteDebugSession(const GdbRemoteDebugSession&) = delete;
    GdbRemoteDebugSession& operator=(const GdbRemoteDebugSession&) = delete;
    GdbRemoteDebugSession(GdbRemoteDebugSession&&) = delete;
    GdbRemoteDebugSession& operator=(GdbRemoteDebugSession&&) = delete;

    ~GdbRemoteDebugSession() noexcept override {
        try {
            const auto cur = state_.load(std::memory_order_acquire);
            if (cur == debugger::DebugSessionState::Paused ||
                cur == debugger::DebugSessionState::Running) {
                (void)detach();
            }
            client_.close();
        } catch (...) {
            // Destructor must never throw.
        }
    }

    [[nodiscard]] Result<void> initialize(
        const GdbRemoteOpenOptions& options,
        std::stop_token stop_token) {
        const std::scoped_lock lock(mutex_);
        client_.set_read_only_mode(false);

        auto caps_res = client_.negotiate(stop_token);
        if (!caps_res) {
            return std::unexpected(caps_res.error());
        }

        if (auto vcont_res = client_.negotiate_vcont(stop_token); vcont_res.has_value()) {
            vcont_ = *vcont_res;
        } else {
            return std::unexpected(vcont_res.error());
        }

        auto halt_reply = client_.send_command("?", stop_token);
        if (!halt_reply) {
            return std::unexpected(halt_reply.error());
        }

        auto initial_stop = parse_rsp_stop_reply_packet(*halt_reply);
        if (!initial_stop) {
            return std::unexpected(initial_stop.error());
        }

        std::optional<RspTargetDescription> negotiated_desc{};
        if (caps_res->qxfer_features_read) {
            auto td = client_.read_target_description(stop_token);
            if (!td) {
                return std::unexpected(td.error());
            }
            negotiated_desc = std::move(*td);
        }

        if (negotiated_desc.has_value()) {
            target_desc_ = std::move(*negotiated_desc);
        } else {
            const Architecture fb_arch =
                options.fallback_architecture.value_or(Architecture::Unknown);
            const bool is32 = fb_arch == Architecture::X86 || fb_arch == Architecture::ARM ||
                              fb_arch == Architecture::RISCV32 || fb_arch == Architecture::PowerPC ||
                              fb_arch == Architecture::MIPS32;
            const bool default_be = fb_arch == Architecture::PowerPC ||
                                    fb_arch == Architecture::PowerPC64 ||
                                    fb_arch == Architecture::MIPS32 ||
                                    fb_arch == Architecture::MIPS64;
            const Endianness fb_endian =
                options.fallback_endianness.value_or(default_be ? Endianness::Big : Endianness::Little);
            const AddressWidth fb_width =
                options.fallback_address_width.value_or(is32 ? AddressWidth::Bits32 : AddressWidth::Bits64);
            target_desc_ = synthesize_debug_fallback_target_description(fb_arch, fb_endian, fb_width);
        }

        if (caps_res->qxfer_auxv_read) {
            if (auto auxv_str = client_.read_qxfer("auxv", "", stop_token);
                auxv_str.has_value() && auxv_str->has_value() && !(*auxv_str)->empty()) {
                const std::string& raw = **auxv_str;
                cached_auxv_.emplace(
                    reinterpret_cast<const std::uint8_t*>(raw.data()),
                    reinterpret_cast<const std::uint8_t*>(raw.data()) + raw.size());
            }
        }

        if (auto initial_threads = client_.enumerate_threads(stop_token);
            initial_threads.has_value()) {
            for (const auto& t : *initial_threads) {
                (void)tid_mapper_.intern(t);
            }
        }

        if (initial_stop->thread.has_value()) {
            fallback_thread_ = *initial_stop->thread;
            active_tid_ = tid_mapper_.intern(*initial_stop->thread);
        }

        if (tid_mapper_.size() == 0u) {
            RspRemoteThreadId fallback_core{};
            fallback_core.multiprocess = false;
            fallback_core.pid_kind = RspIdKind::Any;
            fallback_core.pid = 0u;
            fallback_core.tid_kind = RspIdKind::Explicit;
            fallback_core.tid = 1u;
            fallback_core.wire_token = "1";
            fallback_thread_ = fallback_core;
            active_tid_ = tid_mapper_.intern(fallback_core);
        } else if (active_tid_ == 0u) {
            if (auto threads_list = enumerate_local_threads_locked(); !threads_list.empty()) {
                active_tid_ = threads_list.front().tid;
            }
        }

        std::optional<std::vector<RspLibraryEntry>> initial_libs{};
        if (caps_res->qxfer_libraries_svr4_read || caps_res->qxfer_libraries_read) {
            if (auto libs = client_.read_libraries(stop_token);
                libs.has_value() && libs->has_value()) {
                initial_libs = std::move(**libs);
            }
        }

        populate_profile_and_process_info(initial_libs);
        apply_initial_stop_locked(*initial_stop);
        return {};
    }

    // --- IGdbRemoteDebugSession / IDebugSession ---

    [[nodiscard]] IProcessSession& session() noexcept override { return remote_view_; }
    [[nodiscard]] const IProcessSession& session() const noexcept override { return remote_view_; }
    [[nodiscard]] IGdbRemoteSession& remote_session() noexcept override { return remote_view_; }
    [[nodiscard]] const IGdbRemoteSession& remote_session() const noexcept override {
        return remote_view_;
    }

    [[nodiscard]] const RspVContCapabilities& vcont_capabilities() const noexcept override {
        return vcont_;
    }

    [[nodiscard]] const ProviderFacts& provider_facts() const noexcept override {
        return provider_facts_;
    }

    [[nodiscard]] TargetCapabilityMatrix capability_matrix() const override {
        const std::scoped_lock lock(mutex_);
        return build_capability_matrix_locked();
    }

    [[nodiscard]] debugger::DebugSessionState state() const noexcept override {
        return state_.load(std::memory_order_acquire);
    }

    [[nodiscard]] debugger::DebugStopStatus stop_status() const override {
        const std::scoped_lock lock(mutex_);
        if (state_.load(std::memory_order_acquire) == debugger::DebugSessionState::Running) {
            (void)const_cast<GdbRemoteDebugSession*>(this)->poll_stop_if_running_locked(
                std::chrono::milliseconds{0});
        }
        debugger::DebugStopStatus st = stop_status_;
        st.state = state_.load(std::memory_order_acquire);
        return st;
    }

    [[nodiscard]] Result<void> continue_execution(bool pass_signal_or_exception) override {
        const std::scoped_lock lock(mutex_);
        if (state_.load(std::memory_order_acquire) != debugger::DebugSessionState::Paused) {
            return make_error("continue_execution requires remote target to be in Paused state");
        }
        const std::uint8_t sig =
            (pass_signal_or_exception && last_stop_signal_ > 0)
                ? static_cast<std::uint8_t>(last_stop_signal_)
                : 0u;
        pending_single_step_ = false;
        return send_continue_locked(sig);
    }

    [[nodiscard]] Result<void> pause_execution() override {
        const std::scoped_lock lock(mutex_);
        if (state_.load(std::memory_order_acquire) != debugger::DebugSessionState::Running) {
            return make_error("pause_execution requires remote target to be in Running state");
        }
        return client_.send_interrupt();
    }

    [[nodiscard]] Result<void> step_into(std::optional<ThreadId> tid) override {
        const std::scoped_lock lock(mutex_);
        if (state_.load(std::memory_order_acquire) != debugger::DebugSessionState::Paused) {
            return make_error("step_into requires remote target to be in Paused state");
        }
        const ThreadId target_tid = tid.value_or(active_tid_);
        return step_into_locked(target_tid);
    }

    [[nodiscard]] Result<void> step_over(std::optional<ThreadId> tid) override {
        const std::scoped_lock lock(mutex_);
        if (state_.load(std::memory_order_acquire) != debugger::DebugSessionState::Paused) {
            return make_error("step_over requires remote target to be in Paused state");
        }

        const ThreadId target_tid = tid.value_or(active_tid_);
        const ThreadContext ctx = thread_context_locked(target_tid);
        if (!ctx.status.ok()) {
            return make_error("Failed to read thread context for step_over: " + ctx.status.detail);
        }

        const std::uint64_t ip = ctx.instruction_pointer;
        const bool thumb_mode =
            target_profile_.architecture == Architecture::ARM &&
            ((ip & 1ULL) != 0ULL || (ctx.flags_value.value_or(0ULL) & (1ULL << 5u)) != 0ULL);
        const std::uint64_t fetch_addr =
            thumb_mode ? (ip & ~std::uint64_t{1ULL}) : ip;

        std::array<std::uint8_t, 16> insn_buf{};
        std::size_t valid_len = 0u;
        for (const std::size_t want : {std::size_t{16u}, std::size_t{8u}, std::size_t{4u}, std::size_t{2u}}) {
            auto r = read_memory_shadowed_locked(
                fetch_addr, std::span<std::uint8_t>(insn_buf.data(), want));
            if (r.has_value() && *r > 0u) {
                valid_len = *r;
                break;
            }
        }

        const auto fallthrough = debugger::compute_step_over_fallthrough(
            target_profile_.architecture,
            target_profile_.endianness,
            ip,
            std::span<const std::uint8_t>(insn_buf.data(), valid_len),
            thumb_mode);

        if (!fallthrough.has_value()) {
            return step_into_locked(target_tid);
        }

        return arm_temp_breakpoint_and_continue_locked(target_tid, *fallthrough, thumb_mode);
    }

    [[nodiscard]] Result<void> step_out(std::optional<ThreadId> tid) override {
        const std::scoped_lock lock(mutex_);
        if (state_.load(std::memory_order_acquire) != debugger::DebugSessionState::Paused) {
            return make_error("step_out requires remote target to be in Paused state");
        }

        const ThreadId target_tid = tid.value_or(active_tid_);
        const ThreadContext ctx = thread_context_locked(target_tid);
        if (!ctx.status.ok()) {
            return make_error("Failed to read thread context for step_out: " + ctx.status.detail);
        }

        const TargetLayout layout = target_layout_locked();
        const std::size_t ptr_sz = layout.pointer_size();
        const Architecture arch = target_profile_.architecture;

        std::uint64_t return_va = 0u;
        const bool is_link_reg_isa =
            arch == Architecture::ARM || arch == Architecture::ARM64 ||
            arch == Architecture::RISCV32 || arch == Architecture::RISCV64 ||
            arch == Architecture::PowerPC || arch == Architecture::PowerPC64 ||
            arch == Architecture::MIPS32 || arch == Architecture::MIPS64;

        if (is_link_reg_isa) {
            if (ctx.link_register.has_value() && *ctx.link_register != 0u) {
                return_va = *ctx.link_register;
            } else if (ctx.frame_pointer != 0u) {
                const auto slot_addr =
                    (arch == Architecture::RISCV32 || arch == Architecture::RISCV64)
                        ? ((ctx.frame_pointer >= ptr_sz)
                               ? std::optional<std::uint64_t>{ctx.frame_pointer - ptr_sz}
                               : std::nullopt)
                        : checked_add_u64(ctx.frame_pointer, ptr_sz);
                if (slot_addr.has_value()) {
                    return_va = read_pointer_shadowed_locked(*slot_addr, layout).value_or(0u);
                }
            }
        } else if (arch == Architecture::X86 || arch == Architecture::X86_64) {
            if (ctx.frame_pointer != 0u) {
                if (const auto slot_addr = checked_add_u64(ctx.frame_pointer, ptr_sz);
                    slot_addr.has_value()) {
                    return_va = read_pointer_shadowed_locked(*slot_addr, layout).value_or(0u);
                }
            }
            if (return_va == 0u && ctx.stack_pointer != 0u) {
                return_va = read_pointer_shadowed_locked(ctx.stack_pointer, layout).value_or(0u);
            }
        }

        bool thumb_ret = false;
        if (arch == Architecture::ARM && (return_va & 1ULL) != 0ULL) {
            thumb_ret = true;
            return_va &= ~std::uint64_t{1ULL};
        }

        if (return_va == 0u) {
            return make_error("Unable to determine caller return address for step_out");
        }

        return arm_temp_breakpoint_and_continue_locked(target_tid, return_va, thumb_ret);
    }

    [[nodiscard]] Result<debugger::DebugStopStatus> wait_for_stop(
        std::chrono::milliseconds timeout) override {
        const auto clamped_timeout = std::max(timeout, std::chrono::milliseconds{0});
        const auto deadline = std::chrono::steady_clock::now() + clamped_timeout;

        for (;;) {
            {
                const std::scoped_lock lock(mutex_);
                if (state_.load(std::memory_order_acquire) != debugger::DebugSessionState::Running) {
                    debugger::DebugStopStatus st = stop_status_;
                    st.state = state_.load(std::memory_order_acquire);
                    return st;
                }

                const auto now = std::chrono::steady_clock::now();
                const auto rem =
                    (now < deadline)
                        ? std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now)
                        : std::chrono::milliseconds{0};
                const auto slice = std::min(rem, std::chrono::milliseconds{10});

                auto poll_res = poll_stop_if_running_locked(slice);
                if (!poll_res) {
                    return std::unexpected(poll_res.error());
                }
                if (state_.load(std::memory_order_acquire) != debugger::DebugSessionState::Running) {
                    debugger::DebugStopStatus st = stop_status_;
                    st.state = state_.load(std::memory_order_acquire);
                    return st;
                }
            }

            if (std::chrono::steady_clock::now() >= deadline) {
                return make_error("Timed out waiting for remote GDB target to stop");
            }
        }
    }

    [[nodiscard]] Result<void> detach() override {
        const std::scoped_lock lock(mutex_);
        const auto cur = state_.load(std::memory_order_acquire);
        if (cur == debugger::DebugSessionState::Detached) {
            return {};
        }
        if (cur == debugger::DebugSessionState::Exited) {
            state_.store(debugger::DebugSessionState::Detached, std::memory_order_release);
            stop_status_.state = debugger::DebugSessionState::Detached;
            ++stop_status_.stop_revision;
            client_.close();
            return {};
        }

        if (cur == debugger::DebugSessionState::Running) {
            if (auto intr = client_.send_interrupt(); !intr) {
                return make_error("Failed to interrupt running GDB remote target before detach: " +
                                  intr.error().message);
            }
            if (auto wait_res = poll_until_stopped_locked(std::chrono::milliseconds{1000});
                !wait_res) {
                return make_error("Failed to pause running GDB remote target before detach: " +
                                  wait_res.error().message);
            }
        }

        if (temp_step_bp_.active) {
            if (auto r = disarm_temp_breakpoint_locked(); !r) {
                return r;
            }
        }

        for (RemoteBreakpointEntry& entry : breakpoints_) {
            if (!entry.desc.armed_in_target) {
                continue;
            }
            if (auto r = disarm_breakpoint_entry_locked(entry); !r) {
                // Truthfully retain un-disarmed breakpoint & still-attached session state!
                return r;
            }
        }

        auto d_reply = client_.send_command("D");
        if (!d_reply) {
            return make_error("GDB RSP detach ('D') failed: " + d_reply.error().message);
        }
        std::string_view trimmed = trim_ascii(*d_reply);
        if (trimmed.empty() && client_.capabilities().multiprocess &&
            tid_mapper_.primary_pid() != 0u) {
            auto mp_reply =
                client_.send_command("D;" + format_hex_u64(tid_mapper_.primary_pid()));
            if (!mp_reply) {
                return make_error("GDB RSP multiprocess detach ('D;pid') failed: " +
                                  mp_reply.error().message);
            }
            trimmed = trim_ascii(*mp_reply);
            if (trimmed == "OK") {
                d_reply = std::move(mp_reply);
                trimmed = "OK";
            }
        }

        if (trimmed != "OK") {
            // Retain still-attached state when 'D' is rejected or unsupported.
            return make_error("GDB RSP detach ('D') rejected by stub with '" +
                              std::string(trimmed) + "'");
        }

        state_.store(debugger::DebugSessionState::Detached, std::memory_order_release);
        stop_status_.state = debugger::DebugSessionState::Detached;
        ++stop_status_.stop_revision;
        client_.close();
        return {};
    }

    [[nodiscard]] Result<void> terminate() override {
        const std::scoped_lock lock(mutex_);
        const auto cur = state_.load(std::memory_order_acquire);
        if (cur == debugger::DebugSessionState::Exited ||
            cur == debugger::DebugSessionState::Detached) {
            return {};
        }

        if (cur == debugger::DebugSessionState::Running) {
            (void)client_.send_interrupt();
        }
        (void)client_.send_command_no_reply("k");

        temp_step_bp_ = TempStepBreakpoint{};
        for (RemoteBreakpointEntry& entry : breakpoints_) {
            entry.desc.armed_in_target = false;
        }

        debugger::DebugEvent ev{};
        ev.kind = debugger::DebugEventKind::ProcessExited;
        ev.pid = process_info_.pid;
        ev.tid = active_tid_;
        ev.summary = "Terminated remote GDB target via 'k'";
        push_event_locked(std::move(ev));

        state_.store(debugger::DebugSessionState::Exited, std::memory_order_release);
        stop_status_.state = debugger::DebugSessionState::Exited;
        ++stop_status_.stop_revision;
        client_.close();
        return {};
    }

    [[nodiscard]] Result<debugger::BreakpointDescriptor> add_software_breakpoint(
        std::uint64_t address,
        std::string label,
        bool thumb_mode) override {
        const std::scoped_lock lock(mutex_);
        if (state_.load(std::memory_order_acquire) != debugger::DebugSessionState::Paused) {
            return make_error("Pause the remote target before adding a software breakpoint");
        }

        for (const RemoteBreakpointEntry& existing : breakpoints_) {
            if (existing.desc.kind == debugger::BreakpointKind::Software &&
                existing.desc.address == address) {
                return existing.desc;
            }
        }

        auto trap_spec = debugger::select_software_trap(
            target_profile_.architecture, target_profile_.endianness, thumb_mode);
        if (!trap_spec) {
            return std::unexpected(trap_spec.error());
        }

        std::vector<std::uint8_t> orig_bytes(trap_spec->size, 0u);
        if (auto rd = read_memory_shadowed_locked(address, orig_bytes);
            !rd.has_value() || *rd < orig_bytes.size()) {
            orig_bytes.clear();
        }

        RemoteBreakpointEntry entry{};
        entry.z_type = 0u;
        entry.z_kind = trap_spec->size;
        entry.desc.id = next_breakpoint_id_++;
        entry.desc.kind = debugger::BreakpointKind::Software;
        entry.desc.address = address;
        entry.desc.byte_size = trap_spec->size;
        entry.desc.enabled = true;
        entry.desc.label = std::move(label);
        entry.desc.original_bytes = std::move(orig_bytes);

        if (auto arm_res = arm_breakpoint_entry_locked(entry, trap_spec->span()); !arm_res) {
            return std::unexpected(arm_res.error());
        }

        breakpoints_.push_back(entry);
        return entry.desc;
    }

    [[nodiscard]] ForgivingValue<debugger::BreakpointDescriptor> add_hardware_breakpoint(
        std::uint64_t address,
        debugger::BreakpointKind kind,
        std::uint8_t byte_size,
        std::string label) override {
        if (kind == debugger::BreakpointKind::Software) {
            auto sw = add_software_breakpoint(address, std::move(label), false);
            if (!sw) {
                return ForgivingValue<debugger::BreakpointDescriptor>{
                    .value = std::nullopt,
                    .status = SubsystemStatus::unavailable("gdb_rsp", sw.error().message),
                };
            }
            return ForgivingValue<debugger::BreakpointDescriptor>{
                .value = *sw,
                .status = sw->status,
            };
        }

        std::uint8_t z_type = 1u;
        switch (kind) {
            case debugger::BreakpointKind::HardwareExecute:
                z_type = 1u;
                break;
            case debugger::BreakpointKind::HardwareWrite:
                z_type = 2u;
                break;
            case debugger::BreakpointKind::HardwareRead:
                z_type = 3u;
                break;
            case debugger::BreakpointKind::HardwareReadWrite:
                z_type = 4u;
                break;
            case debugger::BreakpointKind::Software:
                z_type = 0u;
                break;
        }
        return add_hardware_or_watchpoint_impl(address, kind, z_type, byte_size, std::move(label));
    }

    [[nodiscard]] ForgivingValue<debugger::BreakpointDescriptor> add_read_watchpoint(
        std::uint64_t address,
        std::uint8_t byte_size,
        std::string label) override {
        return add_hardware_or_watchpoint_impl(
            address, debugger::BreakpointKind::HardwareRead, 3u, byte_size, std::move(label));
    }

    [[nodiscard]] Result<void> remove_breakpoint(debugger::BreakpointId id) override {
        const std::scoped_lock lock(mutex_);
        if (state_.load(std::memory_order_acquire) != debugger::DebugSessionState::Paused) {
            return make_error("Pause the remote target before removing a breakpoint");
        }

        const auto it = std::ranges::find_if(
            breakpoints_, [id](const RemoteBreakpointEntry& e) { return e.desc.id == id; });
        if (it == breakpoints_.end()) {
            return make_error(std::format("Unknown breakpoint ID {}", id));
        }

        if (it->desc.armed_in_target) {
            if (auto r = disarm_breakpoint_entry_locked(*it); !r) {
                return r;
            }
        }
        breakpoints_.erase(it);
        return {};
    }

    [[nodiscard]] Result<void> set_breakpoint_enabled(
        debugger::BreakpointId id,
        bool enabled) override {
        const std::scoped_lock lock(mutex_);
        if (state_.load(std::memory_order_acquire) != debugger::DebugSessionState::Paused) {
            return make_error("Pause the remote target before toggling a breakpoint");
        }

        const auto it = std::ranges::find_if(
            breakpoints_, [id](const RemoteBreakpointEntry& e) { return e.desc.id == id; });
        if (it == breakpoints_.end()) {
            return make_error(std::format("Unknown breakpoint ID {}", id));
        }
        if (it->desc.enabled == enabled) {
            return {};
        }

        if (!enabled) {
            if (it->desc.armed_in_target) {
                if (auto r = disarm_breakpoint_entry_locked(*it); !r) {
                    return r;
                }
            }
            it->desc.enabled = false;
            it->desc.status = SubsystemStatus::available("gdb_rsp", "Breakpoint disabled");
            return {};
        }

        std::array<std::uint8_t, 4> trap_bytes{};
        std::span<const std::uint8_t> trap_span{};
        if (it->z_type == 0u) {
            auto ts = debugger::select_software_trap(
                target_profile_.architecture,
                target_profile_.endianness,
                it->z_kind == 2u && target_profile_.architecture == Architecture::ARM);
            if (ts.has_value()) {
                trap_bytes = ts->bytes;
                trap_span = std::span<const std::uint8_t>(trap_bytes.data(), ts->size);
            }
        }
        if (auto r = arm_breakpoint_entry_locked(*it, trap_span); !r) {
            return r;
        }
        it->desc.enabled = true;
        return {};
    }

    [[nodiscard]] std::vector<debugger::BreakpointDescriptor> breakpoints() const override {
        const std::scoped_lock lock(mutex_);
        std::vector<debugger::BreakpointDescriptor> out;
        out.reserve(breakpoints_.size());
        for (const RemoteBreakpointEntry& e : breakpoints_) {
            out.push_back(e.desc);
        }
        return out;
    }

    [[nodiscard]] Result<void> write_register(
        ThreadId tid,
        std::string_view reg_name,
        std::uint64_t value_u64) override {
        const std::scoped_lock lock(mutex_);
        if (state_.load(std::memory_order_acquire) != debugger::DebugSessionState::Paused) {
            return make_error("write_register requires remote target to be in Paused state");
        }
        const std::string_view clean_name = trim_ascii(reg_name);
        if (clean_name.empty()) {
            return make_error("Register name must not be empty");
        }

        const RspRegisterSpec* target_spec = nullptr;
        std::size_t g_char_offset = 0u;
        bool offset_accumulating = true;

        for (const RspRegisterSpec& spec : target_desc_.registers) {
            if (matches_register_alias(target_profile_.architecture, spec.name, clean_name)) {
                target_spec = &spec;
                offset_accumulating = false;
                break;
            }
            if (offset_accumulating) {
                g_char_offset += static_cast<std::size_t>((spec.bitsize + 7u) / 8u) * 2u;
            }
        }

        if (target_spec == nullptr) {
            return make_error("Unknown GDB RSP target register '" + std::string(clean_name) + "'");
        }
        if (target_spec->bitsize == 0u) {
            return make_error("Target register '" + target_spec->name + "' has zero bit width");
        }
        if (target_spec->bitsize < 64u && (value_u64 >> target_spec->bitsize) != 0ULL) {
            return make_error(std::format(
                "Value 0x{:X} exceeds {}-bit width of target register '{}'",
                value_u64,
                target_spec->bitsize,
                target_spec->name));
        }

        const auto remote_tid = resolve_or_refresh_remote_tid_locked(tid);
        if (!remote_tid.has_value()) {
            return make_error("Unknown GDB RSP thread ID " + std::to_string(tid));
        }
        if (auto sel = client_.select_general_thread(remote_tid->wire_token); !sel) {
            return sel;
        }

        const std::size_t byte_len = static_cast<std::size_t>((target_spec->bitsize + 7u) / 8u);
        std::vector<std::uint8_t> encoded_bytes(byte_len, 0u);
        if (target_desc_.endianness == Endianness::Big) {
            for (std::size_t i = 0u; i < byte_len; ++i) {
                const std::size_t rev = byte_len - 1u - i;
                encoded_bytes[i] = (rev < 8u)
                                       ? static_cast<std::uint8_t>((value_u64 >> (rev * 8u)) & 0xFFu)
                                       : 0u;
            }
        } else {
            for (std::size_t i = 0u; i < byte_len; ++i) {
                encoded_bytes[i] = (i < 8u)
                                       ? static_cast<std::uint8_t>((value_u64 >> (i * 8u)) & 0xFFu)
                                       : 0u;
            }
        }
        const std::string val_hex = encode_bytes_hex(encoded_bytes);

        auto p_reply =
            client_.send_command("P" + format_hex_u64(target_spec->regnum) + "=" + val_hex);
        if (!p_reply) {
            return std::unexpected(p_reply.error());
        }

        const std::string_view p_trimmed = trim_ascii(*p_reply);
        if (p_trimmed.empty()) {
            // Fallback to full 'g' read + 'G' write when single-register 'P' is unsupported.
            auto g_reply = client_.send_command("g");
            if (!g_reply) {
                return std::unexpected(g_reply.error());
            }
            std::string g_hex(trim_ascii(*g_reply));
            if (is_rsp_error_reply(g_hex) || g_hex.size() < g_char_offset + val_hex.size()) {
                return make_error(
                    "GDB RSP stub rejected 'P' (unsupported) and 'g' buffer is too short for 'G' fallback");
            }
            g_hex.replace(g_char_offset, val_hex.size(), val_hex);
            auto G_reply = client_.send_command("G" + g_hex);
            if (!G_reply) {
                return std::unexpected(G_reply.error());
            }
            if (trim_ascii(*G_reply) != "OK") {
                return make_error("GDB RSP 'G' register bank write failed with '" + *G_reply + "'");
            }
        } else if (p_trimmed != "OK") {
            return make_error("GDB RSP 'P' register write failed with '" +
                              std::string(p_trimmed) + "'");
        }

        inline_reg_overrides_[tid][target_spec->regnum] = val_hex;
        if (target_spec->category == RegisterCategory::InstructionPointer && tid == active_tid_) {
            stop_status_.instruction_pointer = value_u64;
        }
        return {};
    }

    [[nodiscard]] std::vector<debugger::DebugEvent> events() const override {
        const std::scoped_lock lock(mutex_);
        if (state_.load(std::memory_order_acquire) == debugger::DebugSessionState::Running) {
            (void)const_cast<GdbRemoteDebugSession*>(this)->poll_stop_if_running_locked(
                std::chrono::milliseconds{0});
        }
        return events_;
    }

    void clear_events() override {
        const std::scoped_lock lock(mutex_);
        events_.clear();
    }

private:
    class DebugRemoteProcessSession final : public IGdbRemoteSession {
    public:
        explicit DebugRemoteProcessSession(GdbRemoteDebugSession& owner) noexcept
            : owner_(owner) {}

        DebugRemoteProcessSession(const DebugRemoteProcessSession&) = delete;
        DebugRemoteProcessSession& operator=(const DebugRemoteProcessSession&) = delete;
        DebugRemoteProcessSession(DebugRemoteProcessSession&&) = delete;
        DebugRemoteProcessSession& operator=(DebugRemoteProcessSession&&) = delete;
        ~DebugRemoteProcessSession() noexcept override = default;

        [[nodiscard]] const ProcessInfo& info() const noexcept override {
            return owner_.process_info_;
        }

        [[nodiscard]] bool is_alive() const noexcept override {
            const auto st = owner_.state();
            return owner_.client_.is_open() &&
                   st != debugger::DebugSessionState::Exited &&
                   st != debugger::DebugSessionState::Detached;
        }

        [[nodiscard]] bool is_read_only() const noexcept override { return false; }
        [[nodiscard]] bool is_crash_dump() const noexcept override { return false; }

        [[nodiscard]] bool is_suspended() const noexcept override {
            return owner_.state() == debugger::DebugSessionState::Paused;
        }

        [[nodiscard]] TargetLayout target_layout() const noexcept override {
            return owner_.target_layout_locked();
        }

        [[nodiscard]] const TargetProfile& target_profile() const noexcept override {
            return owner_.target_profile_;
        }

        [[nodiscard]] const ProviderFacts& provider_facts() const noexcept override {
            return owner_.provider_facts_;
        }

        [[nodiscard]] TargetCapabilityMatrix capability_matrix() const override {
            return owner_.capability_matrix();
        }

        [[nodiscard]] const RspCapabilities& rsp_capabilities() const noexcept override {
            return owner_.client_.capabilities();
        }

        [[nodiscard]] const RspTargetDescription& target_description() const noexcept override {
            return owner_.target_desc_;
        }

        [[nodiscard]] ProcessInternalsSnapshot process_internals() const override {
            ProcessInternalsSnapshot snap{};
            const bool bare_metal = (owner_.target_profile_.os == OsKind::BareMetal);
            const std::string reason =
                bare_metal
                    ? "OS kernel tables do not exist on bare-metal / QEMU system-mode GDB target"
                    : "GDB RSP debug session does not expose remote OS handle/socket/credential tables";
            snap.handles.status = SubsystemStatus::unavailable("gdb_rsp", reason);
            snap.sockets.status = SubsystemStatus::unavailable("gdb_rsp", reason);
            snap.security.status = SubsystemStatus::unavailable("gdb_rsp", reason);
            return snap;
        }

        [[nodiscard]] std::optional<RspRemoteThreadId> resolve_remote_thread_id(
            ThreadId local_tid) const override {
            const std::scoped_lock lock(owner_.mutex_);
            return owner_.tid_mapper_.lookup_remote(local_tid);
        }

        [[nodiscard]] Result<std::vector<RspRegisterValue>> read_thread_registers(
            ThreadId local_tid) override {
            const std::scoped_lock lock(owner_.mutex_);
            return owner_.read_thread_registers_locked(local_tid);
        }

        [[nodiscard]] Result<std::size_t> read_memory(
            std::uint64_t address,
            std::span<std::uint8_t> buffer) override {
            const std::scoped_lock lock(owner_.mutex_);
            if (owner_.state() != debugger::DebugSessionState::Paused) {
                return make_error("Pause the remote GDB target before reading memory");
            }
            return owner_.read_memory_shadowed_locked(address, buffer);
        }

        [[nodiscard]] Result<std::size_t> write_memory(
            std::uint64_t address,
            std::span<const std::uint8_t> data,
            MemoryWriteOptions /*options*/ = {}) override {
            const std::scoped_lock lock(owner_.mutex_);
            if (owner_.state() != debugger::DebugSessionState::Paused) {
                return make_error("Pause the remote GDB target before writing memory");
            }
            return owner_.write_memory_with_shadow_update_locked(address, data);
        }

        [[nodiscard]] Result<std::vector<MemoryRegion>> memory_regions() override {
            const std::scoped_lock lock(owner_.mutex_);
            if (owner_.state() != debugger::DebugSessionState::Paused) {
                return std::vector<MemoryRegion>{};
            }
            return owner_.memory_regions_locked();
        }

        [[nodiscard]] Result<std::vector<ModuleInfo>> modules() override {
            const std::scoped_lock lock(owner_.mutex_);
            if (owner_.state() != debugger::DebugSessionState::Paused) {
                return std::vector<ModuleInfo>{};
            }
            return owner_.modules_locked();
        }

        [[nodiscard]] Result<void> suspend() override {
            return owner_.pause_execution();
        }

        [[nodiscard]] Result<void> resume() override {
            return owner_.continue_execution(false);
        }

        [[nodiscard]] Result<void> suspend_thread(ThreadId /*tid*/) override {
            return owner_.pause_execution();
        }

        [[nodiscard]] Result<void> resume_thread(ThreadId /*tid*/) override {
            return owner_.continue_execution(false);
        }

        [[nodiscard]] Result<std::vector<ThreadInfo>> threads() override {
            const std::scoped_lock lock(owner_.mutex_);
            if (owner_.state() != debugger::DebugSessionState::Paused) {
                return make_error("Target is currently running or detached; pause before enumerating threads");
            }
            return owner_.enumerate_local_threads_locked();
        }

        [[nodiscard]] ThreadContext thread_context(ThreadId tid) override {
            const std::scoped_lock lock(owner_.mutex_);
            return owner_.thread_context_locked(tid);
        }

        [[nodiscard]] ForgivingValue<std::vector<std::uint8_t>> proc_auxv() override {
            const std::scoped_lock lock(owner_.mutex_);
            if (owner_.cached_auxv_.has_value() && !owner_.cached_auxv_->empty()) {
                return ForgivingValue<std::vector<std::uint8_t>>{
                    .value = *owner_.cached_auxv_,
                    .status = SubsystemStatus::available(
                        "gdb_rsp", "Auxiliary vector read via qXfer:auxv:read"),
                };
            }
            return ForgivingValue<std::vector<std::uint8_t>>{
                .value = std::nullopt,
                .status = SubsystemStatus::unavailable(
                    "gdb_rsp",
                    owner_.target_profile_.os == OsKind::BareMetal
                        ? "Bare-metal GDB stub has no OS auxiliary vector"
                        : "Remote GDB stub did not advertise qXfer:auxv:read+"),
            };
        }

    private:
        GdbRemoteDebugSession& owner_;
    };

    [[nodiscard]] TargetLayout target_layout_locked() const noexcept {
        return TargetLayout{
            .architecture = target_profile_.architecture,
            .address_width = target_profile_.address_width,
            .endianness = target_profile_.endianness,
        };
    }

    [[nodiscard]] TargetCapabilityMatrix build_capability_matrix_locked() const {
        const TargetCapabilityMatrix base = capabilities_for(target_profile_, provider_facts_);
        std::array<Capability, kOperationCount> entries{};
        std::ranges::copy(base.entries(), entries.begin());

        const auto sw_idx = static_cast<std::size_t>(Operation::SoftwareBreakpoints);
        const auto hw_idx = static_cast<std::size_t>(Operation::HardwareWatchpoints);

        const bool arch_has_trap =
            debugger::select_software_trap(
                target_profile_.architecture, target_profile_.endianness, false)
                .has_value();

        if (software_bp_unsupported_) {
            entries[sw_idx] = Capability{
                .operation = Operation::SoftwareBreakpoints,
                .state = SupportState::Unsupported,
                .provider_available = false,
                .provider_name = "gdb_rsp",
                .reason = software_bp_reason_,
            };
        } else if (arch_has_trap) {
            entries[sw_idx] = Capability{
                .operation = Operation::SoftwareBreakpoints,
                .state = (z0_support_ == StubPacketSupport::Unsupported)
                             ? SupportState::Partial
                             : SupportState::SupportedValidated,
                .provider_available = provider_facts_.remote_gdb_stub_available,
                .provider_name = "gdb_rsp",
                .reason = (z0_support_ == StubPacketSupport::Unsupported)
                              ? "Z0 unsupported by stub; using client-side M trap injection + shadow filter"
                              : "GDB RSP Z0/z0 software breakpoints & shadow-read masking supported",
            };
        }

        if (hw_watchpoint_unsupported_) {
            entries[hw_idx] = Capability{
                .operation = Operation::HardwareWatchpoints,
                .state = SupportState::Unsupported,
                .provider_available = false,
                .provider_name = "gdb_rsp",
                .reason = hw_watchpoint_reason_,
            };
        } else if (hw_watchpoint_confirmed_) {
            entries[hw_idx] = Capability{
                .operation = Operation::HardwareWatchpoints,
                .state = SupportState::SupportedValidated,
                .provider_available = provider_facts_.remote_gdb_stub_available,
                .provider_name = "gdb_rsp",
                .reason = "GDB RSP Z1..Z4 hardware breakpoint/watchpoint packet confirmed by stub",
            };
        } else if (target_profile_.architecture != Architecture::Unknown) {
            entries[hw_idx] = Capability{
                .operation = Operation::HardwareWatchpoints,
                .state = entries[hw_idx].is_validated()
                             ? SupportState::SupportedValidated
                             : SupportState::SupportedExperimental,
                .provider_available = provider_facts_.remote_gdb_stub_available,
                .provider_name = "gdb_rsp",
                .reason = "GDB RSP Z1..Z4 hardware breakpoint/watchpoint packets available pending stub probe",
            };
        }

        return TargetCapabilityMatrix(target_profile_, provider_facts_, std::move(entries));
    }

    void populate_profile_and_process_info(
        const std::optional<std::vector<RspLibraryEntry>>& initial_libs) {
        target_profile_.backend = BackendKind::GdbRemote;
        target_profile_.architecture = target_desc_.architecture;
        target_profile_.endianness = target_desc_.endianness;
        target_profile_.address_width = target_desc_.address_width;

        const bool has_elf_os_evidence =
            (cached_auxv_.has_value() && !cached_auxv_->empty()) ||
            client_.capabilities().qxfer_libraries_svr4_read;

        if (target_desc_.os != OsKind::Unknown) {
            target_profile_.os = target_desc_.os;
            target_profile_.abi = target_desc_.abi;
        } else if (has_elf_os_evidence) {
            target_profile_.os = OsKind::Linux;
            target_profile_.abi = AbiKind::GnuLinux;
        } else {
            target_profile_.os = OsKind::BareMetal;
            target_profile_.abi = AbiKind::Standalone;
        }

        if (target_profile_.os == OsKind::Windows) {
            target_profile_.format = Format::PE;
            target_profile_.image_kind = ImageKind::Executable;
        } else if (has_elf_os_evidence ||
                   (target_profile_.os != OsKind::BareMetal &&
                    target_profile_.os != OsKind::Unknown)) {
            target_profile_.format = Format::ELF;
            target_profile_.image_kind = ImageKind::Executable;
        } else {
            target_profile_.format = Format::Unknown;
            target_profile_.image_kind = ImageKind::Unknown;
        }

        provider_facts_ = ProviderFacts::detect_host_providers();
        provider_facts_.remote_gdb_stub_available = true;

        const std::uint64_t raw_pid = tid_mapper_.primary_pid();
        process_info_.pid = (raw_pid > 0u && raw_pid <= 0xFFFF'FFFFu)
                                ? static_cast<ProcessId>(raw_pid)
                                : ProcessId{1u};
        process_info_.architecture = target_profile_.architecture;
        process_info_.endianness = target_profile_.endianness;
        process_info_.is_64bit = (target_profile_.address_width == AddressWidth::Bits64);
        process_info_.access = ProcessAccessStatus::Accessible;
        process_info_.name = "gdb-remote-debug (" + client_.endpoint_description() + ")";

        if (initial_libs.has_value()) {
            for (const auto& lib : *initial_libs) {
                if (lib.is_main_module && !lib.name.empty()) {
                    process_info_.executable_path = std::filesystem::path(lib.name);
                    const std::string fname = process_info_.executable_path.filename().string();
                    if (!fname.empty()) {
                        process_info_.name = fname;
                    }
                    break;
                }
            }
        }
    }

    void apply_initial_stop_locked(const ParsedStopReply& stop) {
        if (stop.kind == ParsedStopReply::Kind::ProcessExit ||
            stop.kind == ParsedStopReply::Kind::SignalTerm) {
            debugger::DebugEvent ev{};
            ev.kind = debugger::DebugEventKind::ProcessExited;
            ev.pid = process_info_.pid;
            ev.tid = active_tid_;
            if (stop.kind == ParsedStopReply::Kind::ProcessExit) {
                ev.exit_code = static_cast<std::int32_t>(stop.signal_or_exit);
                ev.summary = std::format("Remote target exited with code {}", stop.signal_or_exit);
            } else {
                ev.signal_or_exception_code = static_cast<std::int64_t>(stop.signal_or_exit);
                ev.summary = std::format(
                    "Remote target terminated by signal {} (0x{:02X})",
                    stop.signal_or_exit,
                    stop.signal_or_exit);
            }
            push_event_locked(std::move(ev));
            state_.store(debugger::DebugSessionState::Exited, std::memory_order_release);
            stop_status_.state = debugger::DebugSessionState::Exited;
            stop_status_.active_tid = active_tid_;
            ++stop_status_.stop_revision;
            return;
        }

        if (!stop.inline_register_hex.empty() && active_tid_ != 0u) {
            inline_reg_overrides_[active_tid_] = stop.inline_register_hex;
        }
        const std::uint64_t ip = resolve_thread_ip_locked(active_tid_);

        debugger::DebugEvent ev{};
        ev.kind = debugger::DebugEventKind::ProcessStarted;
        ev.pid = process_info_.pid;
        ev.tid = active_tid_;
        ev.address = ip;
        ev.summary = std::format("Attached to GDB remote target at 0x{:X}", ip);
        push_event_locked(std::move(ev));

        state_.store(debugger::DebugSessionState::Paused, std::memory_order_release);
        stop_status_.state = debugger::DebugSessionState::Paused;
        stop_status_.active_tid = active_tid_;
        stop_status_.instruction_pointer = ip;
        stop_status_.stop_revision = 1u;
    }

    [[nodiscard]] std::optional<RspRemoteThreadId> resolve_or_refresh_remote_tid_locked(
        ThreadId local_tid) {
        if (auto found = tid_mapper_.lookup_remote(local_tid); found.has_value()) {
            return found;
        }
        if (auto refreshed = client_.enumerate_threads(); refreshed.has_value()) {
            for (const auto& rt : *refreshed) {
                (void)tid_mapper_.intern(rt);
            }
        }
        return tid_mapper_.lookup_remote(local_tid);
    }

    [[nodiscard]] std::vector<ThreadInfo> enumerate_local_threads_locked() {
        std::vector<RspRemoteThreadId> remote_list;
        if (auto refreshed = client_.enumerate_threads();
            refreshed.has_value() && !refreshed->empty()) {
            remote_list = std::move(*refreshed);
        } else if (fallback_thread_.has_value()) {
            remote_list.push_back(*fallback_thread_);
        }

        std::vector<ThreadInfo> out;
        out.reserve(remote_list.size());
        const bool paused =
            (state_.load(std::memory_order_acquire) == debugger::DebugSessionState::Paused);
        for (const RspRemoteThreadId& rt : remote_list) {
            const ThreadId local_tid = tid_mapper_.intern(rt);
            ThreadInfo ti{};
            ti.tid = local_tid;
            ti.name = "remote-" + rt.wire_token;
            ti.state = paused ? ThreadRunState::Stopped : ThreadRunState::Running;
            ti.is_suspended = paused;
            ti.status = SubsystemStatus::available("gdb_rsp", "Remote thread " + rt.wire_token);
            out.push_back(std::move(ti));
        }
        return out;
    }

    [[nodiscard]] Result<std::vector<RspRegisterValue>> read_thread_registers_locked(
        ThreadId local_tid) {
        if (target_desc_.registers.empty()) {
            return make_error("GDB RSP target description contains zero register definitions");
        }

        const auto remote_tid = resolve_or_refresh_remote_tid_locked(local_tid);
        if (!remote_tid.has_value()) {
            return make_error("Unknown GDB RSP thread ID " + std::to_string(local_tid));
        }

        if (auto sel = client_.select_general_thread(remote_tid->wire_token); !sel) {
            return std::unexpected(sel.error());
        }

        auto regs = client_.read_all_registers(target_desc_);
        if (!regs) {
            // If minimal stub omitted 'g' but supplied inline Txx registers, decode those cleanly.
            const auto inline_it = inline_reg_overrides_.find(local_tid);
            if (inline_it == inline_reg_overrides_.end() || inline_it->second.empty()) {
                return regs;
            }
            std::vector<RspRegisterValue> synthesized;
            synthesized.reserve(target_desc_.registers.size());
            for (const RspRegisterSpec& spec : target_desc_.registers) {
                if (const auto hex_it = inline_it->second.find(spec.regnum);
                    hex_it != inline_it->second.end()) {
                    if (auto dec =
                            decode_rsp_register_hex(spec, hex_it->second, target_desc_.endianness);
                        dec.has_value()) {
                        synthesized.push_back(std::move(*dec));
                        continue;
                    }
                }
                const std::size_t byte_len = static_cast<std::size_t>((spec.bitsize + 7u) / 8u);
                RspRegisterValue unavail{};
                unavail.name = spec.name;
                unavail.regnum = spec.regnum;
                unavail.bit_width =
                    static_cast<std::uint16_t>(std::min<std::uint32_t>(spec.bitsize, 0xFFFFu));
                unavail.category = spec.category;
                unavail.availability = Availability::Unavailable;
                unavail.raw_bytes.assign(byte_len, 0u);
                unavail.valid_bytes.assign(byte_len, 0u);
                unavail.formatted = "unavailable";
                synthesized.push_back(std::move(unavail));
            }
            return synthesized;
        }

        // Overlay any fresher inline expedited stop-reply or P-written register values.
        if (const auto inline_it = inline_reg_overrides_.find(local_tid);
            inline_it != inline_reg_overrides_.end() && !inline_it->second.empty()) {
            for (RspRegisterValue& rv : *regs) {
                const auto hex_it = inline_it->second.find(rv.regnum);
                if (hex_it == inline_it->second.end()) {
                    continue;
                }
                const auto spec_it = std::ranges::find_if(
                    target_desc_.registers,
                    [&rv](const RspRegisterSpec& s) { return s.regnum == rv.regnum; });
                if (spec_it == target_desc_.registers.end()) {
                    continue;
                }
                if (auto dec =
                        decode_rsp_register_hex(*spec_it, hex_it->second, target_desc_.endianness);
                    dec.has_value()) {
                    rv = std::move(*dec);
                }
            }
        }

        return regs;
    }

    [[nodiscard]] std::uint64_t resolve_thread_ip_locked(ThreadId local_tid) {
        if (local_tid == 0u) {
            return 0u;
        }
        // Check inline expedited ProgramCounter first before issuing extra 'g' round-trip if present.
        if (const auto inline_it = inline_reg_overrides_.find(local_tid);
            inline_it != inline_reg_overrides_.end()) {
            for (const RspRegisterSpec& spec : target_desc_.registers) {
                if (spec.category != RegisterCategory::InstructionPointer) {
                    continue;
                }
                if (const auto hex_it = inline_it->second.find(spec.regnum);
                    hex_it != inline_it->second.end()) {
                    if (auto dec =
                            decode_rsp_register_hex(spec, hex_it->second, target_desc_.endianness);
                        dec.has_value() && dec->is_available() && dec->value_u64.has_value()) {
                        return *dec->value_u64;
                    }
                }
            }
        }

        auto regs = read_thread_registers_locked(local_tid);
        if (!regs) {
            return 0u;
        }
        for (const RspRegisterValue& rv : *regs) {
            if (rv.category == RegisterCategory::InstructionPointer && rv.is_available() &&
                rv.value_u64.has_value()) {
                return *rv.value_u64;
            }
        }
        return 0u;
    }

    [[nodiscard]] ThreadContext thread_context_locked(ThreadId tid) {
        ThreadContext ctx{};
        ctx.tid = tid;
        ctx.layout = target_layout_locked();

        if (state_.load(std::memory_order_acquire) != debugger::DebugSessionState::Paused) {
            ctx.status = SubsystemStatus::unavailable(
                "gdb_rsp", "Pause the remote GDB target before reading thread registers");
            return ctx;
        }

        auto regs_res = read_thread_registers_locked(tid);
        if (!regs_res) {
            ctx.status = SubsystemStatus::unavailable("gdb_rsp", regs_res.error().message);
            return ctx;
        }

        std::size_t avail_count = 0u;
        std::size_t missing_count = 0u;
        ctx.registers.reserve(regs_res->size());

        for (std::size_t idx = 0u; idx < regs_res->size(); ++idx) {
            const RspRegisterValue& rr = (*regs_res)[idx];
            if (rr.is_available()) {
                ++avail_count;
            } else {
                ++missing_count;
            }

            if (rr.is_available() && rr.value_u64.has_value()) {
                const std::uint64_t v = *rr.value_u64;
                if (rr.category == RegisterCategory::InstructionPointer &&
                    ctx.instruction_pointer == 0u) {
                    ctx.instruction_pointer = v;
                } else if (rr.category == RegisterCategory::StackPointer &&
                           ctx.stack_pointer == 0u) {
                    ctx.stack_pointer = v;
                } else if (rr.category == RegisterCategory::FramePointer &&
                           ctx.frame_pointer == 0u) {
                    ctx.frame_pointer = v;
                } else if (rr.category == RegisterCategory::Flags &&
                           !ctx.flags_value.has_value()) {
                    ctx.flags_value = v;
                } else if (idx < target_desc_.registers.size() &&
                           is_link_register_spec(
                               target_profile_.architecture, target_desc_.registers[idx]) &&
                           !ctx.link_register.has_value()) {
                    ctx.link_register = v;
                } else if ((rr.name == "fs_base" || rr.name == "tp" ||
                            rr.name == "tpidr_el0" || rr.name == "tpidr") &&
                           !ctx.tls_pointer.has_value()) {
                    ctx.tls_pointer = v;
                }
            }

            RegisterValue rv{};
            rv.name = rr.name;
            rv.category = rr.category;
            rv.bit_width = rr.bit_width;
            rv.value_u64 = rr.is_available() ? rr.value_u64.value_or(0u) : 0u;
            if (rr.is_available()) {
                rv.raw_bytes = rr.raw_bytes;
            }
            rv.formatted = rr.formatted;
            ctx.registers.push_back(std::move(rv));
        }

        if (ctx.flags_value.has_value()) {
            decode_debug_architectural_flags(
                target_profile_.architecture, target_desc_, *ctx.flags_value, ctx.decoded_flags);
        }

        if (avail_count == 0u) {
            ctx.status = SubsystemStatus::unavailable(
                "gdb_rsp",
                "All registers in GDB RSP reply were marked unavailable ('xx') or omitted");
        } else if (missing_count > 0u) {
            ctx.status = SubsystemStatus::partial(
                "gdb_rsp",
                std::to_string(missing_count) +
                    " register(s) reported unavailable ('xx') or partial by GDB RSP stub");
        } else {
            ctx.status = SubsystemStatus::available("gdb_rsp", "GDB RSP register frame decoded");
        }

        return ctx;
    }

    [[nodiscard]] Result<std::size_t> read_memory_shadowed_locked(
        std::uint64_t address,
        std::span<std::uint8_t> buffer) {
        auto got = client_.read_memory(address, buffer);
        if (!got || *got == 0u) {
            return got;
        }

        const std::span<std::uint8_t> valid_span = buffer.subspan(0u, *got);
        std::vector<debugger::BreakpointDescriptor> shadow_list;
        shadow_list.reserve(breakpoints_.size() + (temp_step_bp_.active ? 1u : 0u));
        for (const RemoteBreakpointEntry& e : breakpoints_) {
            shadow_list.push_back(e.desc);
        }
        if (temp_step_bp_.active && temp_step_bp_.armed_own_trap &&
            !temp_step_bp_.original_bytes.empty()) {
            debugger::BreakpointDescriptor tmp{};
            tmp.kind = debugger::BreakpointKind::Software;
            tmp.address = temp_step_bp_.address;
            tmp.armed_in_target = true;
            tmp.original_bytes = temp_step_bp_.original_bytes;
            shadow_list.push_back(std::move(tmp));
        }
        debugger::apply_software_breakpoint_shadow_filter(address, valid_span, shadow_list);
        return got;
    }

    [[nodiscard]] std::optional<std::uint64_t> read_pointer_shadowed_locked(
        std::uint64_t address,
        TargetLayout layout) {
        std::array<std::uint8_t, 8> buf{};
        const std::size_t ptr_sz = layout.pointer_size();
        auto got = read_memory_shadowed_locked(address, std::span<std::uint8_t>(buf.data(), ptr_sz));
        if (!got || *got < ptr_sz) {
            return std::nullopt;
        }
        const EndianReader rd(std::span<const std::uint8_t>(buf.data(), ptr_sz), layout);
        const auto ptr_val = rd.read_pointer(0u);
        return ptr_val.has_value() ? std::optional<std::uint64_t>{*ptr_val} : std::nullopt;
    }

    [[nodiscard]] Result<std::size_t> write_memory_with_shadow_update_locked(
        std::uint64_t address,
        std::span<const std::uint8_t> data) {
        if (data.empty()) {
            return std::size_t{0u};
        }
        const auto write_end = checked_add_u64(address, static_cast<std::uint64_t>(data.size()));
        if (!write_end.has_value()) {
            return make_error("GDB RSP memory write range overflow");
        }

        auto written = client_.write_memory(address, data);
        if (!written) {
            return written;
        }

        // Update saved original_bytes for any overlapping software breakpoints, and re-arm any
        // client-side memory traps whose trap opcode bytes were overwritten by the write.
        for (RemoteBreakpointEntry& entry : breakpoints_) {
            if (entry.desc.kind != debugger::BreakpointKind::Software ||
                entry.desc.original_bytes.empty()) {
                continue;
            }
            const auto bp_end = checked_add_u64(
                entry.desc.address,
                static_cast<std::uint64_t>(entry.desc.original_bytes.size()));
            if (!bp_end.has_value()) {
                continue;
            }
            const std::uint64_t ov_start = std::max(address, entry.desc.address);
            const std::uint64_t ov_end = std::min(*write_end, *bp_end);
            if (ov_start >= ov_end) {
                continue;
            }

            const auto data_off = static_cast<std::size_t>(ov_start - address);
            const auto orig_off = static_cast<std::size_t>(ov_start - entry.desc.address);
            const auto len = static_cast<std::size_t>(ov_end - ov_start);
            std::copy_n(
                data.data() + data_off, len, entry.desc.original_bytes.data() + orig_off);

            if (entry.desc.armed_in_target && entry.used_client_memory_trap) {
                if (auto ts = debugger::select_software_trap(
                        target_profile_.architecture,
                        target_profile_.endianness,
                        entry.z_kind == 2u && target_profile_.architecture == Architecture::ARM);
                    ts.has_value()) {
                    (void)client_.write_memory(entry.desc.address, ts->span());
                }
            }
        }

        return written;
    }

    [[nodiscard]] Result<std::vector<MemoryRegion>> memory_regions_locked() {
        if (client_.capabilities().qxfer_memory_map_read) {
            auto mmap_res = client_.read_memory_map();
            if (mmap_res.has_value() && mmap_res->has_value() && !(*mmap_res)->empty()) {
                std::vector<MemoryRegion> out;
                out.reserve((*mmap_res)->size());
                for (const auto& m : **mmap_res) {
                    const auto end = checked_add_u64(m.start, m.length);
                    if (!end.has_value() || *end <= m.start) {
                        continue;
                    }
                    MemoryRegion r{};
                    r.start_address = m.start;
                    r.end_address = *end;
                    r.protection = parse_debug_memory_map_protection(m);
                    r.kind = MemoryRegionKind::Anonymous;
                    r.pathname = m.name.empty() ? std::string(to_string(m.type)) : m.name;
                    r.usage.committed_bytes = m.length;
                    r.usage.vm_flags = std::string(to_string(m.type));
                    out.push_back(std::move(r));
                }
                return out;
            }
        }
        if (cached_auxv_.has_value() && !cached_auxv_->empty()) {
            return probe_elf_pt_load_regions_from_auxv_locked(*cached_auxv_);
        }
        return std::vector<MemoryRegion>{};
    }

    [[nodiscard]] std::vector<MemoryRegion> probe_elf_pt_load_regions_from_auxv_locked(
        std::span<const std::uint8_t> auxv_bytes) {
        const TargetLayout layout = target_layout_locked();
        const std::size_t word_sz = layout.pointer_size();
        const std::size_t pair_sz = word_sz * 2u;
        if (auxv_bytes.size() < pair_sz) {
            return {};
        }

        const EndianReader er(auxv_bytes, layout);
        std::uint64_t at_phdr = 0u;
        std::uint64_t at_phent = 0u;
        std::uint64_t at_phnum = 0u;
        std::uint64_t at_pagesz = 4096u;

        for (std::size_t off = 0u; off + pair_sz <= auxv_bytes.size(); off += pair_sz) {
            const auto tag = er.read_pointer(off);
            const auto val = er.read_pointer(off + word_sz);
            if (!tag.has_value() || !val.has_value() || *tag == 0u) {
                break;
            }
            switch (*tag) {
                case 3u: at_phdr = *val; break;
                case 4u: at_phent = *val; break;
                case 5u: at_phnum = *val; break;
                case 6u:
                    if (*val >= 512u && (*val & (*val - 1u)) == 0u) {
                        at_pagesz = *val;
                    }
                    break;
                default:
                    break;
            }
        }

        const std::size_t expected_phent = layout.is_64bit() ? 56u : 32u;
        if (at_phdr == 0u || at_phent < expected_phent || at_phent > 128u ||
            at_phnum == 0u || at_phnum > 256u) {
            return {};
        }
        const auto total_ph_bytes = checked_mul_u64(at_phent, at_phnum);
        if (!total_ph_bytes.has_value() || *total_ph_bytes > 32768u) {
            return {};
        }

        std::vector<std::uint8_t> ph_buf(static_cast<std::size_t>(*total_ph_bytes));
        auto got = read_memory_shadowed_locked(at_phdr, ph_buf);
        if (!got.has_value() || *got < ph_buf.size()) {
            return {};
        }

        const EndianReader ph_er(ph_buf, layout);
        std::optional<std::uint64_t> load_bias{};
        for (std::uint64_t i = 0u; i < at_phnum; ++i) {
            const auto off = static_cast<std::size_t>(i * at_phent);
            const std::uint32_t p_type = ph_er.read_u32(off).value_or(0u);
            if (p_type == 6u) {
                const std::uint64_t p_vaddr = layout.is_64bit()
                                                  ? ph_er.read_u64(off + 16u).value_or(0u)
                                                  : ph_er.read_u32(off + 8u).value_or(0u);
                if (at_phdr >= p_vaddr) {
                    load_bias = at_phdr - p_vaddr;
                }
                break;
            }
        }
        const std::uint64_t bias = load_bias.value_or(0u);
        const std::uint64_t page_mask = ~(at_pagesz - 1u);

        std::vector<MemoryRegion> regions;
        for (std::uint64_t i = 0u; i < at_phnum; ++i) {
            const auto off = static_cast<std::size_t>(i * at_phent);
            const std::uint32_t p_type = ph_er.read_u32(off).value_or(0u);
            if (p_type != 1u) {
                continue;
            }
            const std::uint32_t p_flags = layout.is_64bit()
                                              ? ph_er.read_u32(off + 4u).value_or(0u)
                                              : ph_er.read_u32(off + 24u).value_or(0u);
            const std::uint64_t p_offset = layout.is_64bit()
                                               ? ph_er.read_u64(off + 8u).value_or(0u)
                                               : ph_er.read_u32(off + 4u).value_or(0u);
            const std::uint64_t p_vaddr = layout.is_64bit()
                                              ? ph_er.read_u64(off + 16u).value_or(0u)
                                              : ph_er.read_u32(off + 8u).value_or(0u);
            const std::uint64_t p_memsz = layout.is_64bit()
                                              ? ph_er.read_u64(off + 40u).value_or(0u)
                                              : ph_er.read_u32(off + 20u).value_or(0u);
            if (p_memsz == 0u) {
                continue;
            }
            const auto biased_start = checked_add_u64(p_vaddr, bias);
            if (!biased_start.has_value()) {
                continue;
            }
            const auto raw_end = checked_add_u64(*biased_start, p_memsz);
            if (!raw_end.has_value()) {
                continue;
            }
            const std::uint64_t aligned_start = *biased_start & page_mask;
            const auto padded_end = checked_add_u64(*raw_end, at_pagesz - 1u);
            const std::uint64_t aligned_end =
                padded_end.has_value() ? (*padded_end & page_mask) : *raw_end;
            if (aligned_end <= aligned_start) {
                continue;
            }

            MemoryRegion reg{};
            reg.start_address = aligned_start;
            reg.end_address = aligned_end;
            reg.protection.readable = (p_flags & 0x4u) != 0u;
            reg.protection.writable = (p_flags & 0x2u) != 0u;
            reg.protection.executable = (p_flags & 0x1u) != 0u;
            reg.kind = MemoryRegionKind::Image;
            reg.file_offset = p_offset & page_mask;
            reg.pathname = process_info_.executable_path.empty()
                               ? "[auxv:PT_LOAD]"
                               : process_info_.executable_path.string();
            reg.module_name = process_info_.name;
            reg.usage.committed_bytes = aligned_end - aligned_start;
            reg.usage.vm_flags = "auxv:PT_LOAD";
            regions.push_back(std::move(reg));
        }

        std::ranges::sort(regions, {}, &MemoryRegion::start_address);
        return regions;
    }

    [[nodiscard]] Result<std::vector<ModuleInfo>> modules_locked() {
        if (!client_.capabilities().qxfer_libraries_svr4_read &&
            !client_.capabilities().qxfer_libraries_read) {
            return std::vector<ModuleInfo>{};
        }
        auto libs_res = client_.read_libraries();
        if (!libs_res.has_value() || !libs_res->has_value()) {
            return std::vector<ModuleInfo>{};
        }

        std::vector<ModuleInfo> out;
        out.reserve((*libs_res)->size());
        for (const auto& lib : **libs_res) {
            ModuleInfo mod{};
            mod.path = std::filesystem::path(lib.name);
            mod.name = mod.path.filename().string();
            if (mod.name.empty()) {
                mod.name = lib.name.empty() ? "[remote-module]" : lib.name;
            }
            mod.base_address = lib.base_address;
            mod.is_main_module = lib.is_main_module;
            mod.format = target_profile_.format;

            std::array<std::uint8_t, 64> hdr{};
            if (auto n = read_memory_shadowed_locked(mod.base_address, hdr);
                n.has_value() && *n >= 4u) {
                if (hdr[0] == 0x7Fu && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F') {
                    mod.format = Format::ELF;
                    if (*n >= 32u) {
                        const EndianReader er(
                            std::span<const std::uint8_t>(hdr.data(), *n), target_layout_locked());
                        mod.entry_point = target_layout_locked().is_64bit()
                                              ? er.read_u64(24u).value_or(0u)
                                              : er.read_u32(24u).value_or(0u);
                    }
                } else if (hdr[0] == 'M' && hdr[1] == 'Z') {
                    mod.format = Format::PE;
                }
            }
            out.push_back(std::move(mod));
        }
        return out;
    }

    [[nodiscard]] ForgivingValue<debugger::BreakpointDescriptor> add_hardware_or_watchpoint_impl(
        std::uint64_t address,
        debugger::BreakpointKind kind,
        std::uint8_t z_type,
        std::uint8_t byte_size,
        std::string label) {
        const std::scoped_lock lock(mutex_);
        if (state_.load(std::memory_order_acquire) != debugger::DebugSessionState::Paused) {
            return ForgivingValue<debugger::BreakpointDescriptor>{
                .value = std::nullopt,
                .status = SubsystemStatus::unavailable(
                    "gdb_rsp", "Pause the remote target before adding a hardware breakpoint/watchpoint"),
            };
        }

        std::uint32_t z_kind = byte_size;
        if (z_type == 1u) {
            if (auto ts = debugger::select_software_trap(
                    target_profile_.architecture, target_profile_.endianness, false);
                ts.has_value()) {
                z_kind = ts->size;
            } else if (z_kind == 0u) {
                z_kind = 4u;
            }
        } else {
            if (byte_size != 1u && byte_size != 2u && byte_size != 4u && byte_size != 8u) {
                return ForgivingValue<debugger::BreakpointDescriptor>{
                    .value = std::nullopt,
                    .status = SubsystemStatus::unavailable(
                        "gdb_rsp",
                        std::format("Invalid hardware watchpoint byte_size {} (must be 1, 2, 4, or 8)",
                                    byte_size)),
                };
            }
        }

        const std::string cmd = "Z" + std::to_string(z_type) + "," +
                                format_hex_u64(address) + "," + format_hex_u64(z_kind);
        auto reply = client_.send_command(cmd);
        if (!reply) {
            return ForgivingValue<debugger::BreakpointDescriptor>{
                .value = std::nullopt,
                .status = SubsystemStatus::unavailable("gdb_rsp", reply.error().message),
            };
        }

        const std::string_view trimmed = trim_ascii(*reply);
        if (trimmed.empty()) {
            hw_watchpoint_unsupported_ = true;
            hw_watchpoint_confirmed_ = false;
            hw_watchpoint_reason_ = std::format(
                "Remote GDB stub replied empty (\"\") to Z{} packet (hardware watchpoints unsupported)",
                z_type);
            return ForgivingValue<debugger::BreakpointDescriptor>{
                .value = std::nullopt,
                .status = SubsystemStatus::unavailable("gdb_rsp", hw_watchpoint_reason_),
            };
        }
        if (trimmed != "OK") {
            return ForgivingValue<debugger::BreakpointDescriptor>{
                .value = std::nullopt,
                .status = SubsystemStatus::unavailable(
                    "gdb_rsp",
                    std::format("Remote GDB stub rejected Z{} at 0x{:X} with '{}'",
                                z_type,
                                address,
                                trimmed)),
            };
        }

        hw_watchpoint_confirmed_ = true;
        hw_watchpoint_unsupported_ = false;

        RemoteBreakpointEntry entry{};
        entry.z_type = z_type;
        entry.z_kind = z_kind;
        entry.desc.id = next_breakpoint_id_++;
        entry.desc.kind = kind;
        entry.desc.address = address;
        entry.desc.byte_size = static_cast<std::uint8_t>(std::min<std::uint32_t>(z_kind, 255u));
        entry.desc.enabled = true;
        entry.desc.armed_in_target = true;
        entry.desc.label = std::move(label);
        entry.desc.status = SubsystemStatus::available(
            "gdb_rsp", std::format("Armed GDB RSP Z{} hardware breakpoint/watchpoint", z_type));

        breakpoints_.push_back(entry);
        return ForgivingValue<debugger::BreakpointDescriptor>{
            .value = entry.desc,
            .status = entry.desc.status,
        };
    }

    [[nodiscard]] Result<void> arm_breakpoint_entry_locked(
        RemoteBreakpointEntry& entry,
        std::span<const std::uint8_t> fallback_trap_bytes) {
        const std::string cmd = "Z" + std::to_string(entry.z_type) + "," +
                                format_hex_u64(entry.desc.address) + "," +
                                format_hex_u64(entry.z_kind);
        auto reply = client_.send_command(cmd);
        if (!reply) {
            return std::unexpected(reply.error());
        }

        const std::string_view trimmed = trim_ascii(*reply);
        if (trimmed == "OK") {
            if (entry.z_type == 0u) {
                z0_support_ = StubPacketSupport::Supported;
                software_bp_unsupported_ = false;
            }
            entry.used_client_memory_trap = false;
            entry.desc.armed_in_target = true;
            entry.desc.status = SubsystemStatus::available(
                "gdb_rsp", std::format("Armed GDB RSP Z{} breakpoint", entry.z_type));
            return {};
        }

        if (trimmed.empty() && entry.z_type == 0u) {
            z0_support_ = StubPacketSupport::Unsupported;
            if (!fallback_trap_bytes.empty() &&
                entry.desc.original_bytes.size() == fallback_trap_bytes.size()) {
                if (auto wr = client_.write_memory(entry.desc.address, fallback_trap_bytes);
                    wr.has_value()) {
                    entry.used_client_memory_trap = true;
                    entry.desc.armed_in_target = true;
                    entry.desc.status = SubsystemStatus::available(
                        "gdb_rsp",
                        "Armed client-side software trap via 'M' (stub omitted Z0)");
                    return {};
                }
            }
            software_bp_unsupported_ = true;
            software_bp_reason_ =
                "Remote GDB stub replied empty (\"\") to Z0 and client-side 'M' trap fallback failed";
            return make_error(software_bp_reason_);
        }

        if (trimmed.empty()) {
            hw_watchpoint_unsupported_ = true;
            hw_watchpoint_confirmed_ = false;
            hw_watchpoint_reason_ = std::format(
                "Remote GDB stub replied empty (\"\") to Z{} (unsupported)", entry.z_type);
            return make_error(hw_watchpoint_reason_);
        }

        return make_error(std::format(
            "GDB RSP Z{} at 0x{:X} failed with '{}'",
            entry.z_type,
            entry.desc.address,
            trimmed));
    }

    [[nodiscard]] Result<void> disarm_breakpoint_entry_locked(RemoteBreakpointEntry& entry) {
        if (!entry.desc.armed_in_target) {
            return {};
        }

        if (entry.used_client_memory_trap) {
            auto wr = client_.write_memory(entry.desc.address, entry.desc.original_bytes);
            if (!wr) {
                return make_error(std::format(
                    "Failed to restore software trap bytes at 0x{:X}: {}",
                    entry.desc.address,
                    wr.error().message));
            }
            entry.desc.armed_in_target = false;
            entry.used_client_memory_trap = false;
            return {};
        }

        const std::string cmd = "z" + std::to_string(entry.z_type) + "," +
                                format_hex_u64(entry.desc.address) + "," +
                                format_hex_u64(entry.z_kind);
        auto reply = client_.send_command(cmd);
        if (!reply) {
            return make_error(std::format(
                "Failed to disarm GDB RSP z{} breakpoint #{} at 0x{:X}: {}",
                entry.z_type,
                entry.desc.id,
                entry.desc.address,
                reply.error().message));
        }

        const std::string_view trimmed = trim_ascii(*reply);
        if (trimmed != "OK") {
            return make_error(std::format(
                "GDB RSP z{} disarm for breakpoint #{} at 0x{:X} rejected with '{}'",
                entry.z_type,
                entry.desc.id,
                entry.desc.address,
                trimmed));
        }

        entry.desc.armed_in_target = false;
        return {};
    }

    [[nodiscard]] RemoteBreakpointEntry* find_armed_software_bp_locked(
        std::uint64_t address) noexcept {
        for (RemoteBreakpointEntry& e : breakpoints_) {
            if (e.desc.kind == debugger::BreakpointKind::Software &&
                e.desc.armed_in_target && e.desc.address == address) {
                return &e;
            }
        }
        return nullptr;
    }

    [[nodiscard]] Result<void> arm_temp_breakpoint_and_continue_locked(
        ThreadId tid,
        std::uint64_t target_address,
        bool thumb_mode) {
        if (temp_step_bp_.active) {
            (void)disarm_temp_breakpoint_locked();
        }

        active_tid_ = tid;
        pending_single_step_ = false;

        if (find_armed_software_bp_locked(target_address) != nullptr) {
            temp_step_bp_ = TempStepBreakpoint{
                .active = true,
                .armed_own_trap = false,
                .used_client_memory_trap = false,
                .address = target_address,
                .z_kind = 1u,
                .original_bytes = {},
            };
            if (auto r = send_continue_locked(0u); !r) {
                temp_step_bp_ = TempStepBreakpoint{};
                return r;
            }
            return {};
        }

        auto trap_spec = debugger::select_software_trap(
            target_profile_.architecture, target_profile_.endianness, thumb_mode);
        if (!trap_spec) {
            return std::unexpected(trap_spec.error());
        }

        std::vector<std::uint8_t> orig_bytes(trap_spec->size, 0u);
        if (auto rd = read_memory_shadowed_locked(target_address, orig_bytes);
            !rd.has_value() || *rd < orig_bytes.size()) {
            orig_bytes.clear();
        }

        const std::string z_cmd =
            "Z0," + format_hex_u64(target_address) + "," + format_hex_u64(trap_spec->size);
        auto z_reply = client_.send_command(z_cmd);
        if (!z_reply) {
            return std::unexpected(z_reply.error());
        }

        bool used_mem_trap = false;
        const std::string_view z_trimmed = trim_ascii(*z_reply);
        if (z_trimmed == "OK") {
            z0_support_ = StubPacketSupport::Supported;
        } else if (z_trimmed.empty() && orig_bytes.size() == trap_spec->size) {
            z0_support_ = StubPacketSupport::Unsupported;
            auto wr = client_.write_memory(target_address, trap_spec->span());
            if (!wr) {
                return std::unexpected(wr.error());
            }
            used_mem_trap = true;
        } else {
            return make_error(std::format(
                "Failed to arm temporary step Z0 breakpoint at 0x{:X} ('{}')",
                target_address,
                z_trimmed));
        }

        temp_step_bp_ = TempStepBreakpoint{
            .active = true,
            .armed_own_trap = true,
            .used_client_memory_trap = used_mem_trap,
            .address = target_address,
            .z_kind = trap_spec->size,
            .original_bytes = std::move(orig_bytes),
        };

        if (auto cont_res = send_continue_locked(0u); !cont_res) {
            (void)disarm_temp_breakpoint_locked();
            return cont_res;
        }
        return {};
    }

    [[nodiscard]] Result<void> disarm_temp_breakpoint_locked() {
        if (!temp_step_bp_.active) {
            return {};
        }
        if (!temp_step_bp_.armed_own_trap) {
            temp_step_bp_ = TempStepBreakpoint{};
            return {};
        }

        if (temp_step_bp_.used_client_memory_trap) {
            auto wr = client_.write_memory(temp_step_bp_.address, temp_step_bp_.original_bytes);
            if (!wr) {
                return make_error("Failed to restore temporary step breakpoint bytes: " +
                                  wr.error().message);
            }
            temp_step_bp_ = TempStepBreakpoint{};
            return {};
        }

        const std::string z_cmd = "z0," + format_hex_u64(temp_step_bp_.address) + "," +
                                  format_hex_u64(temp_step_bp_.z_kind);
        auto reply = client_.send_command(z_cmd);
        if (!reply) {
            return make_error("Failed to disarm temporary step z0 breakpoint: " +
                              reply.error().message);
        }
        if (trim_ascii(*reply) != "OK") {
            return make_error("Temporary step z0 disarm rejected with '" + *reply + "'");
        }
        temp_step_bp_ = TempStepBreakpoint{};
        return {};
    }

    [[nodiscard]] Result<void> select_continue_thread_locked(std::string_view wire_token) {
        const std::string cmd = "Hc" + std::string(wire_token.empty() ? "-1" : wire_token);
        auto reply = client_.send_command(cmd);
        if (!reply) {
            return std::unexpected(reply.error());
        }
        const std::string_view trimmed = trim_ascii(*reply);
        if (trimmed == "OK" || trimmed.empty()) {
            return {};
        }
        if (is_rsp_error_reply(trimmed)) {
            return make_error("GDB RSP thread selection " + cmd + " failed with '" +
                              std::string(trimmed) + "'");
        }
        return {};
    }

    [[nodiscard]] Result<void> send_continue_locked(std::uint8_t signal_code) {
        last_stop_signal_ = 0;
        inline_reg_overrides_.clear();
        client_.reset_selected_thread();

        std::string resume_cmd;
        if (signal_code != 0u) {
            if (vcont_.supported && vcont_.cont_signal) {
                resume_cmd = std::format("vCont;C{:02x}", signal_code);
            } else {
                if (auto hc = select_continue_thread_locked("-1"); !hc) {
                    return hc;
                }
                resume_cmd = std::format("C{:02x}", signal_code);
            }
        } else {
            if (vcont_.supported && vcont_.cont) {
                resume_cmd = "vCont;c";
            } else {
                if (auto hc = select_continue_thread_locked("-1"); !hc) {
                    return hc;
                }
                resume_cmd = "c";
            }
        }

        if (auto tx = client_.send_command_no_reply(resume_cmd); !tx) {
            return tx;
        }
        state_.store(debugger::DebugSessionState::Running, std::memory_order_release);
        stop_status_.state = debugger::DebugSessionState::Running;
        return {};
    }

    [[nodiscard]] Result<void> step_into_locked(ThreadId target_tid) {
        const auto remote_tid = resolve_or_refresh_remote_tid_locked(target_tid);
        const std::string wire_token =
            remote_tid.has_value() ? remote_tid->wire_token : std::string{};

        active_tid_ = target_tid;
        last_stop_signal_ = 0;
        pending_single_step_ = true;
        inline_reg_overrides_.clear();
        client_.reset_selected_thread();

        std::string step_cmd;
        if (vcont_.supported && vcont_.step) {
            step_cmd = wire_token.empty() ? "vCont;s" : ("vCont;s:" + wire_token);
        } else {
            if (auto hc = select_continue_thread_locked(wire_token.empty() ? "0" : wire_token);
                !hc) {
                return hc;
            }
            step_cmd = "s";
        }

        if (auto tx = client_.send_command_no_reply(step_cmd); !tx) {
            pending_single_step_ = false;
            return tx;
        }
        state_.store(debugger::DebugSessionState::Running, std::memory_order_release);
        stop_status_.state = debugger::DebugSessionState::Running;
        return {};
    }

    [[nodiscard]] Result<void> poll_until_stopped_locked(std::chrono::milliseconds timeout) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (state_.load(std::memory_order_acquire) == debugger::DebugSessionState::Running) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                return make_error("Timed out waiting for remote GDB stop reply");
            }
            const auto rem =
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
            if (auto r = poll_stop_if_running_locked(std::min(rem, std::chrono::milliseconds{20}));
                !r) {
                return r;
            }
        }
        return {};
    }

    [[nodiscard]] Result<void> poll_stop_if_running_locked(std::chrono::milliseconds slice_timeout) {
        bool first_poll = true;
        while (state_.load(std::memory_order_acquire) == debugger::DebugSessionState::Running) {
            const auto wait_slice = first_poll ? slice_timeout : std::chrono::milliseconds{0};
            first_poll = false;

            auto pkt_res = client_.try_receive_packet(wait_slice);
            if (!pkt_res) {
                return std::unexpected(pkt_res.error());
            }
            if (!pkt_res->has_value()) {
                return {};
            }

            const std::string_view pkt = trim_ascii(**pkt_res);
            if (pkt.size() >= 3u && pkt.front() == 'O' && pkt != "OK") {
                if (const auto console_out = decode_hex_ascii(pkt.substr(1u));
                    console_out.has_value()) {
                    debugger::DebugEvent out_ev{};
                    out_ev.kind = debugger::DebugEventKind::DebugOutput;
                    out_ev.pid = process_info_.pid;
                    out_ev.tid = active_tid_;
                    out_ev.summary = *console_out;
                    push_event_locked(std::move(out_ev));
                    continue;
                }
            }

            return handle_stop_reply_locked(pkt);
        }
        return {};
    }

    [[nodiscard]] Result<void> handle_stop_reply_locked(std::string_view raw_pkt) {
        auto parsed = parse_rsp_stop_reply_packet(raw_pkt);
        if (!parsed) {
            return std::unexpected(parsed.error());
        }

        const bool was_single_step = pending_single_step_;
        pending_single_step_ = false;

        if (parsed->kind == ParsedStopReply::Kind::ProcessExit ||
            parsed->kind == ParsedStopReply::Kind::SignalTerm) {
            temp_step_bp_ = TempStepBreakpoint{};
            for (RemoteBreakpointEntry& e : breakpoints_) {
                e.desc.armed_in_target = false;
            }

            debugger::DebugEvent ev{};
            ev.kind = debugger::DebugEventKind::ProcessExited;
            ev.pid = process_info_.pid;
            ev.tid = active_tid_;
            if (parsed->kind == ParsedStopReply::Kind::ProcessExit) {
                ev.exit_code = static_cast<std::int32_t>(parsed->signal_or_exit);
                ev.summary = std::format(
                    "Remote target exited with code {}", parsed->signal_or_exit);
            } else {
                ev.signal_or_exception_code = static_cast<std::int64_t>(parsed->signal_or_exit);
                ev.summary = std::format(
                    "Remote target terminated by signal {} (0x{:02X})",
                    parsed->signal_or_exit,
                    parsed->signal_or_exit);
            }
            push_event_locked(std::move(ev));
            state_.store(debugger::DebugSessionState::Exited, std::memory_order_release);
            stop_status_.state = debugger::DebugSessionState::Exited;
            ++stop_status_.stop_revision;
            return {};
        }

        // Signal stop (`Sxx` or `Txx`)
        ThreadId stopped_tid = active_tid_;
        if (parsed->thread.has_value()) {
            stopped_tid = tid_mapper_.intern(*parsed->thread);
        }
        active_tid_ = stopped_tid;

        if (!parsed->inline_register_hex.empty() && stopped_tid != 0u) {
            inline_reg_overrides_[stopped_tid] = parsed->inline_register_hex;
        }

        std::uint64_t ip = resolve_thread_ip_locked(stopped_tid);
        const std::uint8_t sig = parsed->signal_or_exit;

        const bool had_temp_bp = temp_step_bp_.active;
        const std::uint64_t temp_bp_addr = temp_step_bp_.address;
        const bool temp_used_mem_trap = temp_step_bp_.used_client_memory_trap;
        if (had_temp_bp) {
            (void)disarm_temp_breakpoint_locked();
        }

        constexpr std::uint8_t kSigTrap = 0x05u;

        // 1. Hardware watchpoint stop (`watch:`, `rwatch:`, `awatch:`)
        if (parsed->watch_address.has_value()) {
            last_stop_signal_ = 0;
            const std::uint64_t waddr = *parsed->watch_address;
            RemoteBreakpointEntry* matched_wp = nullptr;
            for (RemoteBreakpointEntry& e : breakpoints_) {
                if (!e.desc.armed_in_target || e.z_type < 2u) {
                    continue;
                }
                const std::uint64_t span_len = std::max<std::uint64_t>(1u, e.z_kind);
                const auto wend = checked_add_u64(e.desc.address, span_len);
                if (waddr >= e.desc.address && wend.has_value() && waddr < *wend) {
                    matched_wp = &e;
                    break;
                }
            }

            debugger::DebugEvent ev{};
            ev.kind = debugger::DebugEventKind::BreakpointHit;
            ev.pid = process_info_.pid;
            ev.tid = stopped_tid;
            ev.address = waddr;
            if (matched_wp != nullptr) {
                ++matched_wp->desc.hit_count;
                ev.breakpoint_id = matched_wp->desc.id;
                ev.summary = std::format(
                    "Hit {} watchpoint #{} at 0x{:X} (IP 0x{:X}, hits: {})",
                    parsed->watch_kind,
                    matched_wp->desc.id,
                    waddr,
                    ip,
                    matched_wp->desc.hit_count);
            } else {
                ev.summary = std::format(
                    "Hit {} watchpoint at 0x{:X} (IP 0x{:X})", parsed->watch_kind, waddr, ip);
            }
            finalize_paused_stop_locked(stopped_tid, ip, std::move(ev));
            return {};
        }

        // 2. SIGTRAP (`0x05`): check user software/hardware execute breakpoints & step completion
        if (sig == kSigTrap) {
            last_stop_signal_ = 0;
            const auto trap_spec = debugger::select_software_trap(
                target_profile_.architecture, target_profile_.endianness, false);

            RemoteBreakpointEntry* hit_bp = find_armed_breakpoint_at_pc_locked(ip, trap_spec);
            if (hit_bp != nullptr && hit_bp->used_client_memory_trap &&
                trap_spec.has_value() && trap_spec->rewinds_pc_on_hit &&
                ip != hit_bp->desc.address) {
                rewind_pc_locked(stopped_tid, hit_bp->desc.address);
                ip = hit_bp->desc.address;
            }

            const bool hit_temp =
                had_temp_bp &&
                (ip == temp_bp_addr ||
                 (temp_used_mem_trap && trap_spec.has_value() && trap_spec->rewinds_pc_on_hit &&
                  ip == temp_bp_addr + trap_spec->size));
            if (hit_temp && temp_used_mem_trap && ip != temp_bp_addr) {
                rewind_pc_locked(stopped_tid, temp_bp_addr);
                ip = temp_bp_addr;
            }

            if (hit_bp != nullptr) {
                ++hit_bp->desc.hit_count;
                debugger::DebugEvent ev{};
                ev.kind = debugger::DebugEventKind::BreakpointHit;
                ev.pid = process_info_.pid;
                ev.tid = stopped_tid;
                ev.address = hit_bp->desc.address;
                ev.breakpoint_id = hit_bp->desc.id;
                ev.summary = std::format(
                    "Hit {} breakpoint #{} at 0x{:X}{} (hits: {})",
                    debugger::to_string(hit_bp->desc.kind),
                    hit_bp->desc.id,
                    hit_bp->desc.address,
                    hit_bp->desc.label.empty() ? "" : (" <" + hit_bp->desc.label + ">"),
                    hit_bp->desc.hit_count);
                finalize_paused_stop_locked(stopped_tid, ip, std::move(ev));
                return {};
            }

            if (was_single_step || hit_temp) {
                debugger::DebugEvent ev{};
                ev.kind = debugger::DebugEventKind::SingleStepCompleted;
                ev.pid = process_info_.pid;
                ev.tid = stopped_tid;
                ev.address = ip;
                ev.summary = std::format("Step completed at 0x{:X}", ip);
                finalize_paused_stop_locked(stopped_tid, ip, std::move(ev));
                return {};
            }

            debugger::DebugEvent ev{};
            ev.kind = debugger::DebugEventKind::ExceptionOrSignal;
            ev.pid = process_info_.pid;
            ev.tid = stopped_tid;
            ev.address = ip;
            ev.signal_or_exception_code = static_cast<std::int64_t>(sig);
            ev.summary = std::format("Stopped on SIGTRAP at 0x{:X}", ip);
            finalize_paused_stop_locked(stopped_tid, ip, std::move(ev));
            return {};
        }

        // 3. Non-SIGTRAP signal stop (e.g. `0x02` SIGINT from `0x03` pause, `0x0B` SIGSEGV, etc.)
        last_stop_signal_ = static_cast<int>(sig);
        debugger::DebugEvent ev{};
        ev.kind = debugger::DebugEventKind::ExceptionOrSignal;
        ev.pid = process_info_.pid;
        ev.tid = stopped_tid;
        ev.address = ip;
        ev.signal_or_exception_code = static_cast<std::int64_t>(sig);
        ev.summary = std::format("Stopped on signal {} (0x{:02X}) at 0x{:X}", sig, sig, ip);
        finalize_paused_stop_locked(stopped_tid, ip, std::move(ev));
        return {};
    }

    [[nodiscard]] RemoteBreakpointEntry* find_armed_breakpoint_at_pc_locked(
        std::uint64_t ip,
        const Result<debugger::SoftwareTrapSpec>& trap_spec) noexcept {
        for (RemoteBreakpointEntry& e : breakpoints_) {
            if (!e.desc.armed_in_target) {
                continue;
            }
            if (e.z_type == 0u || e.z_type == 1u) {
                if (e.desc.address == ip) {
                    return &e;
                }
                if (e.used_client_memory_trap && trap_spec.has_value() &&
                    trap_spec->rewinds_pc_on_hit && ip >= trap_spec->size &&
                    (ip - trap_spec->size) == e.desc.address) {
                    return &e;
                }
            }
        }
        return nullptr;
    }

    void rewind_pc_locked(ThreadId tid, std::uint64_t rewound_ip) {
        for (const RspRegisterSpec& spec : target_desc_.registers) {
            if (spec.category != RegisterCategory::InstructionPointer || spec.bitsize == 0u) {
                continue;
            }
            const std::size_t byte_len = static_cast<std::size_t>((spec.bitsize + 7u) / 8u);
            std::vector<std::uint8_t> enc(byte_len, 0u);
            if (target_desc_.endianness == Endianness::Big) {
                for (std::size_t i = 0u; i < byte_len; ++i) {
                    const std::size_t rev = byte_len - 1u - i;
                    enc[i] = (rev < 8u)
                                 ? static_cast<std::uint8_t>((rewound_ip >> (rev * 8u)) & 0xFFu)
                                 : 0u;
                }
            } else {
                for (std::size_t i = 0u; i < byte_len; ++i) {
                    enc[i] = (i < 8u) ? static_cast<std::uint8_t>((rewound_ip >> (i * 8u)) & 0xFFu)
                                      : 0u;
                }
            }
            const std::string val_hex = encode_bytes_hex(enc);
            if (const auto remote_tid = tid_mapper_.lookup_remote(tid); remote_tid.has_value()) {
                (void)client_.select_general_thread(remote_tid->wire_token);
            }
            (void)client_.send_command("P" + format_hex_u64(spec.regnum) + "=" + val_hex);
            inline_reg_overrides_[tid][spec.regnum] = val_hex;
            break;
        }
    }

    void finalize_paused_stop_locked(
        ThreadId stopped_tid,
        std::uint64_t ip,
        debugger::DebugEvent ev) {
        push_event_locked(std::move(ev));
        state_.store(debugger::DebugSessionState::Paused, std::memory_order_release);
        stop_status_.state = debugger::DebugSessionState::Paused;
        stop_status_.active_tid = stopped_tid;
        stop_status_.instruction_pointer = ip;
        ++stop_status_.stop_revision;
    }

    void push_event_locked(debugger::DebugEvent ev) {
        ev.sequence = ++next_event_seq_;
        stop_status_.last_event = ev;
        events_.push_back(std::move(ev));
        if (events_.size() > 4096u) {
            events_.erase(events_.begin(), events_.begin() + 512);
        }
    }

    mutable std::mutex mutex_{};
    RspClient client_;
    DebugRemoteProcessSession remote_view_;
    RspVContCapabilities vcont_{};
    ProcessInfo process_info_{};
    TargetProfile target_profile_{};
    ProviderFacts provider_facts_{};
    RspTargetDescription target_desc_{};
    RspThreadIdMapper tid_mapper_{};
    std::optional<RspRemoteThreadId> fallback_thread_{};
    std::optional<std::vector<std::uint8_t>> cached_auxv_{};

    std::atomic<debugger::DebugSessionState> state_{debugger::DebugSessionState::Idle};
    debugger::DebugStopStatus stop_status_{};
    ThreadId active_tid_{0};
    int last_stop_signal_{0};
    bool pending_single_step_{false};

    debugger::BreakpointId next_breakpoint_id_{1};
    std::vector<RemoteBreakpointEntry> breakpoints_{};
    TempStepBreakpoint temp_step_bp_{};

    StubPacketSupport z0_support_{StubPacketSupport::Unprobed};
    bool software_bp_unsupported_{false};
    std::string software_bp_reason_{};
    bool hw_watchpoint_confirmed_{false};
    bool hw_watchpoint_unsupported_{false};
    std::string hw_watchpoint_reason_{};

    std::unordered_map<ThreadId, std::unordered_map<std::uint32_t, std::string>>
        inline_reg_overrides_{};
    std::uint64_t next_event_seq_{0};
    std::vector<debugger::DebugEvent> events_{};
};

}  // namespace

// ---------------------------------------------------------------------------
// GdbRemoteBackend::open_debug entry points
// ---------------------------------------------------------------------------

Result<std::unique_ptr<debugger::IDebugSession>> GdbRemoteBackend::open_debug(
    std::unique_ptr<IRspTransport> transport,
    ExplicitDebugConsent consent,
    const GdbRemoteOpenOptions& options,
    std::stop_token stop_token) {
    if (!consent.acknowledged_target_mutation) {
        return make_error(
            "GdbRemoteBackend::open_debug refused: ExplicitDebugConsent::acknowledged_target_mutation "
            "must be true before opening an opt-in mutating remote debug session");
    }
    if (transport == nullptr || !transport->is_open()) {
        return make_error("GdbRemoteBackend::open_debug requires an open IRspTransport");
    }

    RspClientOptions client_opts = options.rsp;
    client_opts.strict_read_only = false;

    RspClient client(std::move(transport), client_opts);
    auto session = std::make_unique<GdbRemoteDebugSession>(std::move(client));
    if (auto init_res = session->initialize(options, stop_token); !init_res) {
        return std::unexpected(init_res.error());
    }
    return session;
}

Result<std::unique_ptr<debugger::IDebugSession>> GdbRemoteBackend::open_debug(
    const GdbRemoteOpenOptions& options,
    ExplicitDebugConsent consent,
    std::stop_token stop_token) {
    if (!consent.acknowledged_target_mutation) {
        return make_error(
            "GdbRemoteBackend::open_debug refused: ExplicitDebugConsent::acknowledged_target_mutation "
            "must be true before opening an opt-in mutating remote debug session");
    }
    auto transport = TcpRspTransport::connect(options.endpoint, stop_token);
    if (!transport) {
        return std::unexpected(transport.error());
    }
    return open_debug(std::move(*transport), consent, options, stop_token);
}

Result<std::unique_ptr<debugger::IDebugSession>> GdbRemoteBackend::open_debug(
    const RemoteEndpointOptions& endpoint,
    ExplicitDebugConsent consent,
    std::stop_token stop_token) {
    if (!consent.acknowledged_target_mutation) {
        return make_error(
            "GdbRemoteBackend::open_debug refused: ExplicitDebugConsent::acknowledged_target_mutation "
            "must be true before opening an opt-in mutating remote debug session");
    }
    GdbRemoteOpenOptions opts{};
    opts.endpoint = endpoint;
    return open_debug(opts, consent, stop_token);
}

Result<std::unique_ptr<debugger::IDebugSession>> GdbRemoteBackend::open_debug(
    std::string_view endpoint_spec,
    ExplicitDebugConsent consent,
    bool allow_unencrypted_remote_endpoint,
    std::stop_token stop_token) {
    if (!consent.acknowledged_target_mutation) {
        return make_error(
            "GdbRemoteBackend::open_debug refused: ExplicitDebugConsent::acknowledged_target_mutation "
            "must be true before opening an opt-in mutating remote debug session");
    }
    RemoteEndpointOptions defaults{};
    defaults.allow_unencrypted_remote_endpoint = allow_unencrypted_remote_endpoint;
    auto ep = parse_gdb_remote_endpoint(endpoint_spec, defaults);
    if (!ep) {
        return std::unexpected(ep.error());
    }
    return open_debug(*ep, consent, stop_token);
}

}  // namespace peelf
