#pragma once

// Clean-room GDB Remote Serial Protocol (RSP) transport, framing, XML target
// negotiation, and strictly read-only IProcessSession backend (WU-25a).

#include <peelf/binary_image.hpp>
#include <peelf/capability_matrix.hpp>
#include <peelf/endian_reader.hpp>
#include <peelf/error.hpp>
#include <peelf/forgiving.hpp>
#include <peelf/process.hpp>
#include <peelf/process_internals.hpp>
#include <peelf/provenance.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace peelf {

/// TCP endpoint connection options and security trust policy for GDB RSP stubs.
struct RemoteEndpointOptions {
    std::string host{"127.0.0.1"};
    std::uint16_t port{1234};
    /// Security gate: GDB RSP runs in cleartext with arbitrary remote command risk.
    /// Non-loopback endpoints (`127.0.0.0/8`, `::1`, `localhost` resolving strictly to loopback)
    /// are rejected unless this flag is explicitly enabled by the caller.
    bool allow_unencrypted_remote_endpoint{false};
    std::chrono::milliseconds connect_timeout{3000};
    std::chrono::milliseconds io_timeout{2000};
    bool enable_tcp_nodelay{true};
};

/// Parses `"host:port"`, `"[ipv6]:port"`, `"tcp:host:port"`, or `":port"` into `RemoteEndpointOptions`.
[[nodiscard]] Result<RemoteEndpointOptions> parse_gdb_remote_endpoint(
    std::string_view endpoint,
    RemoteEndpointOptions defaults = {});

/// Returns true if `host` is a syntactic loopback literal (`127.0.0.0/8`, `::1`, `::ffff:127.x.y.z`,
/// or `localhost`). Resolved socket addresses are still verified independently prior to `connect()`.
[[nodiscard]] bool is_loopback_endpoint_host(std::string_view host) noexcept;

enum class RspIoStatus : std::uint8_t {
    Ok = 0,
    Timeout,
    EndOfStream,
    Cancelled,
};

[[nodiscard]] constexpr std::string_view to_string(RspIoStatus status) noexcept {
    switch (status) {
        case RspIoStatus::Ok:          return "Ok";
        case RspIoStatus::Timeout:     return "Timeout";
        case RspIoStatus::EndOfStream: return "EndOfStream";
        case RspIoStatus::Cancelled:   return "Cancelled";
    }
    return "Ok";
}

struct RspReadOutcome {
    RspIoStatus status{RspIoStatus::Ok};
    std::size_t bytes_read{0};
};

/// Abstract byte-stream transport for GDB Remote Serial Protocol sessions.
class IRspTransport {
public:
    virtual ~IRspTransport() = default;

    [[nodiscard]] virtual Result<RspReadOutcome> read_some(
        std::span<std::uint8_t> buffer,
        std::chrono::milliseconds timeout,
        std::stop_token stop_token = {}) = 0;

    [[nodiscard]] virtual Result<void> write_all(
        std::span<const std::uint8_t> data,
        std::chrono::milliseconds timeout,
        std::stop_token stop_token = {}) = 0;

    [[nodiscard]] virtual bool is_open() const noexcept = 0;
    virtual void close() noexcept = 0;
    [[nodiscard]] virtual std::string endpoint_description() const = 0;
};

/// Cross-platform move-only RAII non-blocking TCP socket transport (`Winsock2` on `_WIN32`,
/// POSIX sockets + `poll()` on UNIX).
class TcpRspTransport final : public IRspTransport {
public:
#ifdef _WIN32
    using NativeSocketHandle = std::uintptr_t;
    static constexpr NativeSocketHandle kInvalidSocket = ~NativeSocketHandle{0};
#else
    using NativeSocketHandle = int;
    static constexpr NativeSocketHandle kInvalidSocket = -1;
#endif

    TcpRspTransport() noexcept = default;
    TcpRspTransport(const TcpRspTransport&) = delete;
    TcpRspTransport& operator=(const TcpRspTransport&) = delete;
    TcpRspTransport(TcpRspTransport&& other) noexcept;
    TcpRspTransport& operator=(TcpRspTransport&& other) noexcept;
    ~TcpRspTransport() noexcept override;

    [[nodiscard]] static Result<std::unique_ptr<TcpRspTransport>> connect(
        const RemoteEndpointOptions& options,
        std::stop_token stop_token = {});

    [[nodiscard]] Result<RspReadOutcome> read_some(
        std::span<std::uint8_t> buffer,
        std::chrono::milliseconds timeout,
        std::stop_token stop_token = {}) override;

    [[nodiscard]] Result<void> write_all(
        std::span<const std::uint8_t> data,
        std::chrono::milliseconds timeout,
        std::stop_token stop_token = {}) override;

    [[nodiscard]] bool is_open() const noexcept override;
    void close() noexcept override;
    [[nodiscard]] std::string endpoint_description() const override { return endpoint_desc_; }

private:
    TcpRspTransport(NativeSocketHandle handle, std::string endpoint_desc) noexcept;

    NativeSocketHandle socket_{kInvalidSocket};
    std::string endpoint_desc_{};
};

// ---------------------------------------------------------------------------
// Pure RSP framing, escaping, RLE, and checksum utilities
// ---------------------------------------------------------------------------

/// Computes the 8-bit modulo-256 RSP checksum of raw wire bytes between `$` and `#`.
[[nodiscard]] std::uint8_t compute_rsp_checksum(std::string_view wire_payload) noexcept;

/// Escapes `$` (`0x24`), `#` (`0x23`), `}` (`0x7d`), and `*` (`0x2a`) as `}` followed by `byte ^ 0x20`.
[[nodiscard]] std::string rsp_escape_payload(std::string_view raw_payload);

/// Frames `raw_payload` into `$escaped#csum`.
[[nodiscard]] std::string rsp_encode_frame(std::string_view raw_payload);

/// Expands RSP `}` (`0x7d ^ 0x20`) escapes and `*` run-length encoding in a single bounded pass.
[[nodiscard]] Result<std::string> rsp_decode_wire_payload(
    std::string_view wire_payload,
    std::size_t max_decoded_bytes = 16u * 1024u * 1024u);

/// Returns true if `payload` represents any target-mutating or execution-altering RSP packet
/// (`M`, `X`, `G`, `P`, `Z*`, `z*`, `vKill`, `k`, `vCont`, `c`/`C`, `s`/`S`, `vRun`, `R`, `vFlash*`, `!`).
[[nodiscard]] bool is_mutating_rsp_packet(std::string_view payload) noexcept;

// ---------------------------------------------------------------------------
// Negotiated RSP capabilities, XML target description, memory-map, & threads
// ---------------------------------------------------------------------------

struct RspClientOptions {
    std::chrono::milliseconds command_timeout{2000};
    std::size_t max_retries{3};
    std::size_t max_packet_size{16384};
    std::size_t max_annex_size{16u * 1024u * 1024u};
    std::size_t max_xi_include_depth{8};
    std::size_t max_xi_include_documents{64};
    bool request_no_ack_mode{true};
    bool strict_read_only{false};
};

struct RspCapabilities {
    std::size_t packet_size{1024};
    bool no_ack_mode_supported{false};
    bool no_ack_mode_active{false};
    bool multiprocess{false};
    bool qxfer_features_read{false};
    bool qxfer_memory_map_read{false};
    bool qxfer_libraries_svr4_read{false};
    bool qxfer_libraries_read{false};
    bool qxfer_auxv_read{false};
    std::vector<std::string> raw_features{};
};

/// Parses a semicolon-delimited `qSupported` stub reply into `RspCapabilities`.
[[nodiscard]] RspCapabilities parse_qsupported_reply(
    std::string_view reply,
    std::size_t max_client_packet_size = 65536);

struct RspFlagFieldSpec {
    std::string name{};
    std::uint8_t start_bit{0};
    std::uint8_t end_bit{0};
};

struct RspFlagsTypeSpec {
    std::string id{};
    std::uint32_t byte_size{0};
    std::vector<RspFlagFieldSpec> fields{};
};

struct RspRegisterSpec {
    std::string name{};
    std::uint32_t regnum{0};
    std::uint32_t bitsize{0};
    std::string type{};
    std::string group{};
    std::string feature_name{};
    RegisterCategory category{RegisterCategory::General};
    bool save_restore{true};
};

struct RspTargetDescription {
    std::string raw_architecture{};
    std::string raw_osabi{};
    Architecture architecture{Architecture::Unknown};
    Endianness endianness{Endianness::Little};
    AddressWidth address_width{AddressWidth::Bits64};
    bool explicit_endianness{false};
    OsKind os{OsKind::Unknown};
    AbiKind abi{AbiKind::Unknown};
    std::vector<std::string> feature_names{};
    std::vector<RspFlagsTypeSpec> flags_types{};
    std::vector<RspRegisterSpec> registers{};
};

struct RspRegisterValue {
    std::string name{};
    std::uint32_t regnum{0};
    std::uint16_t bit_width{0};
    RegisterCategory category{RegisterCategory::General};
    Availability availability{Availability::Unavailable};
    std::optional<std::uint64_t> value_u64{};
    std::vector<std::uint8_t> raw_bytes{};
    std::vector<std::uint8_t> valid_bytes{};
    std::string formatted{};

    [[nodiscard]] constexpr bool is_available() const noexcept {
        return availability == Availability::Available;
    }
    [[nodiscard]] constexpr bool is_partial() const noexcept {
        return availability == Availability::Partial;
    }
    [[nodiscard]] constexpr bool is_unavailable() const noexcept {
        return availability == Availability::Unavailable;
    }
};

using AnnexFetcherFn = std::function<Result<std::string>(std::string_view annex_name)>;

/// Bounded, non-networked XML parser for `target.xml` and nested `<xi:include href="..."/>` annexes.
[[nodiscard]] Result<RspTargetDescription> parse_rsp_target_xml(
    std::string_view root_xml,
    const AnnexFetcherFn& fetch_annex = {},
    std::size_t max_include_depth = 8,
    std::size_t max_include_documents = 64);

/// Decodes a single register's hex/`xx` slice (`2 * (spec.bitsize / 8)` chars) according to `endianness`,
/// preserving `xx` unavailable bytes (`Availability::Unavailable` / `Availability::Partial`) without
/// zero-filling them as valid.
[[nodiscard]] Result<RspRegisterValue> decode_rsp_register_hex(
    const RspRegisterSpec& spec,
    std::string_view hex_or_xx,
    Endianness endianness);

/// Decodes a `g`-packet hex/`xx` buffer against `description.registers` (ordered by `regnum`).
[[nodiscard]] Result<std::vector<RspRegisterValue>> decode_rsp_g_packet(
    const RspTargetDescription& description,
    std::string_view g_hex_payload);

enum class RspMemoryRegionType : std::uint8_t {
    Ram = 0,
    Rom,
    Flash,
    Unknown,
};

[[nodiscard]] constexpr std::string_view to_string(RspMemoryRegionType type) noexcept {
    switch (type) {
        case RspMemoryRegionType::Ram:     return "ram";
        case RspMemoryRegionType::Rom:     return "rom";
        case RspMemoryRegionType::Flash:   return "flash";
        case RspMemoryRegionType::Unknown: return "unknown";
    }
    return "unknown";
}

struct RspMemoryMapEntry {
    RspMemoryRegionType type{RspMemoryRegionType::Ram};
    std::uint64_t start{0};
    std::uint64_t length{0};
    std::optional<std::uint64_t> blocksize{};
    std::string name{};
    std::string permissions{};
};

/// Bounded non-networked XML parser for `qXfer:memory-map:read::`.
[[nodiscard]] Result<std::vector<RspMemoryMapEntry>> parse_rsp_memory_map_xml(
    std::string_view xml);

struct RspLibraryEntry {
    std::string name{};
    std::uint64_t base_address{0};
    std::uint64_t dynamic_address{0};
    std::uint64_t link_map_address{0};
    std::vector<std::uint64_t> segment_addresses{};
    bool is_main_module{false};
};

/// Bounded non-networked XML parser for `qXfer:libraries-svr4:read::` and `qXfer:libraries:read::`.
[[nodiscard]] Result<std::vector<RspLibraryEntry>> parse_rsp_libraries_xml(
    std::string_view xml);

enum class RspIdKind : std::uint8_t {
    All = 0,       ///< `-1` sentinel ("all processes" or "all threads")
    Any = 1,       ///< `0` sentinel ("any process" or "any thread")
    Explicit = 2,  ///< Positive 64-bit hex ID
};

struct RspRemoteThreadId {
    bool multiprocess{false};
    RspIdKind pid_kind{RspIdKind::Any};
    std::uint64_t pid{0};
    RspIdKind tid_kind{RspIdKind::Explicit};
    std::uint64_t tid{0};
    std::string wire_token{};

    [[nodiscard]] constexpr bool is_concrete_thread() const noexcept {
        return tid_kind == RspIdKind::Explicit &&
               (!multiprocess || pid_kind == RspIdKind::Explicit);
    }

    [[nodiscard]] constexpr bool is_negative_sentinel() const noexcept {
        return pid_kind == RspIdKind::All || tid_kind == RspIdKind::All;
    }

    auto operator<=>(const RspRemoteThreadId&) const = default;
};

/// Parses a single GDB RSP thread-id (`<tid>`, `-1`, `0`, `p<pid>.<tid>`, `p<pid>.-1`, `p-1.-1`).
[[nodiscard]] Result<RspRemoteThreadId> parse_rsp_thread_id(std::string_view token);

/// Parses a `qfThreadInfo` / `qsThreadInfo` reply (`"m<id>,<id>..."` or `"l"`).
[[nodiscard]] Result<std::vector<RspRemoteThreadId>> parse_rsp_thread_info_packet(
    std::string_view reply,
    bool& reached_end);

/// Collision-free bijection mapping arbitrary 64-bit / multiprocess `RspRemoteThreadId` tokens
/// onto 32-bit `peelf::ThreadId` handles without silent truncation collisions.
class RspThreadIdMapper {
public:
    explicit RspThreadIdMapper(std::uint64_t primary_pid = 0) noexcept
        : primary_pid_(primary_pid) {}

    void set_primary_pid(std::uint64_t pid) noexcept { primary_pid_ = pid; }
    [[nodiscard]] std::uint64_t primary_pid() const noexcept { return primary_pid_; }

    /// Assigns or retrieves a collision-free `ThreadId` for `remote_id`.
    [[nodiscard]] ThreadId intern(const RspRemoteThreadId& remote_id);

    [[nodiscard]] std::optional<RspRemoteThreadId> lookup_remote(ThreadId local_tid) const;
    [[nodiscard]] std::optional<ThreadId> lookup_local(std::string_view wire_token) const;
    [[nodiscard]] std::size_t size() const noexcept { return local_to_remote_.size(); }

private:
    std::uint64_t primary_pid_{0};
    ThreadId next_synthetic_tid_{0x8000'0001u};
    std::unordered_map<std::string, ThreadId> wire_to_local_{};
    std::unordered_map<ThreadId, RspRemoteThreadId> local_to_remote_{};
};

// ---------------------------------------------------------------------------
// Stateful GDB RSP protocol engine
// ---------------------------------------------------------------------------

class RspClient {
public:
    RspClient(std::unique_ptr<IRspTransport> transport, RspClientOptions options = {});

    RspClient(const RspClient&) = delete;
    RspClient& operator=(const RspClient&) = delete;
    RspClient(RspClient&&) noexcept = default;
    RspClient& operator=(RspClient&&) noexcept = default;
    ~RspClient() noexcept = default;

    [[nodiscard]] bool is_open() const noexcept {
        return transport_ != nullptr && transport_->is_open();
    }
    void close() noexcept {
        if (transport_ != nullptr) {
            transport_->close();
        }
    }

    [[nodiscard]] std::string endpoint_description() const {
        return transport_ != nullptr ? transport_->endpoint_description() : std::string{};
    }

    void set_read_only_mode(bool enabled) noexcept { options_.strict_read_only = enabled; }
    [[nodiscard]] bool is_read_only_mode() const noexcept { return options_.strict_read_only; }
    [[nodiscard]] bool is_no_ack_mode() const noexcept { return no_ack_mode_; }
    [[nodiscard]] const RspCapabilities& capabilities() const noexcept { return capabilities_; }

    /// Sends one RSP command payload (`$escaped#csum`), handles `+`/`-` ACK/NAK retries (unless
    /// `QStartNoAckMode` is active), verifies reply checksum (NAKing corrupt frames in ACK mode),
    /// and returns the unescaped & RLE-expanded reply payload.
    [[nodiscard]] Result<std::string> send_command(
        std::string_view payload,
        std::stop_token stop_token = {});

    /// Negotiates `qSupported` and (when supported and enabled) `QStartNoAckMode`.
    [[nodiscard]] Result<RspCapabilities> negotiate(std::stop_token stop_token = {});

    /// Explicitly requests `QStartNoAckMode` transition; returns `true` if `"OK"`.
    [[nodiscard]] Result<bool> enable_no_ack_mode(std::stop_token stop_token = {});

    /// Reads an entire `qXfer:<object>:read:<annex>:<offset>,<length>` stream across `m`/`l` chunks,
    /// enforcing `options_.max_annex_size`. Returns `std::nullopt` when the stub replies `""` (unsupported).
    [[nodiscard]] Result<std::optional<std::string>> read_qxfer(
        std::string_view object,
        std::string_view annex = {},
        std::stop_token stop_token = {});

    /// Reads and parses `qXfer:features:read:target.xml` plus `<xi:include href="..."/>` annexes.
    [[nodiscard]] Result<std::optional<RspTargetDescription>> read_target_description(
        std::stop_token stop_token = {});

    /// Reads and parses `qXfer:memory-map:read::`.
    [[nodiscard]] Result<std::optional<std::vector<RspMemoryMapEntry>>> read_memory_map(
        std::stop_token stop_token = {});

    /// Reads and parses `qXfer:libraries-svr4:read::` or fallback `qXfer:libraries:read::`.
    [[nodiscard]] Result<std::optional<std::vector<RspLibraryEntry>>> read_libraries(
        std::stop_token stop_token = {});

    /// Enumerates remote threads via `qfThreadInfo` / `qsThreadInfo` (with `qC` fallback).
    [[nodiscard]] Result<std::vector<RspRemoteThreadId>> enumerate_threads(
        std::stop_token stop_token = {});

    /// Selects thread `wire_token` for general register reads via `Hg<wire_token>`.
    [[nodiscard]] Result<void> select_general_thread(
        std::string_view wire_token,
        std::stop_token stop_token = {});

    /// Reads all registers via `g` and decodes them against `description` (also probing individual
    /// `p<hex_regnum>` registers when `description` specifies registers beyond the `g` buffer).
    [[nodiscard]] Result<std::vector<RspRegisterValue>> read_all_registers(
        const RspTargetDescription& description,
        std::stop_token stop_token = {});

    /// Reads a single register via `p<hex_regnum>`.
    [[nodiscard]] Result<RspRegisterValue> read_single_register(
        const RspRegisterSpec& spec,
        Endianness endianness,
        std::stop_token stop_token = {});

    /// Reads target memory via chunked hex `m<addr>,<len>` packets without mutating target state.
    [[nodiscard]] Result<std::size_t> read_memory(
        std::uint64_t address,
        std::span<std::uint8_t> buffer,
        std::stop_token stop_token = {});

private:
    [[nodiscard]] Result<std::uint8_t> read_byte(
        std::chrono::milliseconds timeout,
        std::stop_token stop_token);

    [[nodiscard]] Result<std::string> receive_packet_with_nak_retries(
        std::stop_token stop_token);

    std::unique_ptr<IRspTransport> transport_{};
    RspClientOptions options_{};
    RspCapabilities capabilities_{};
    bool no_ack_mode_{false};
    std::string selected_hg_thread_{};
    std::vector<std::uint8_t> rx_buffer_{};
    std::size_t rx_offset_{0};
};

// ---------------------------------------------------------------------------
// Read-only GDB Remote IProcessSession & GdbRemoteBackend
// ---------------------------------------------------------------------------

struct GdbRemoteOpenOptions {
    RemoteEndpointOptions endpoint{};
    RspClientOptions rsp{};
    std::optional<Architecture> fallback_architecture{};
    std::optional<Endianness> fallback_endianness{};
    std::optional<AddressWidth> fallback_address_width{};
};

/// Extended read-only session interface exposing negotiated GDB RSP capabilities,
/// `TargetProfile` (`BackendKind::GdbRemote`), `ProviderFacts`, and provenance-stamped
/// collections alongside the standard `IProcessSession` contract.
class IGdbRemoteSession : public IProcessSession {
public:
    ~IGdbRemoteSession() override = default;

    [[nodiscard]] bool is_read_only() const noexcept override { return true; }
    [[nodiscard]] bool is_crash_dump() const noexcept override { return false; }

    [[nodiscard]] virtual const TargetProfile& target_profile() const noexcept = 0;
    [[nodiscard]] virtual const ProviderFacts& provider_facts() const noexcept = 0;
    [[nodiscard]] virtual TargetCapabilityMatrix capability_matrix() const = 0;
    [[nodiscard]] virtual const RspCapabilities& rsp_capabilities() const noexcept = 0;
    [[nodiscard]] virtual const RspTargetDescription& target_description() const noexcept = 0;
    [[nodiscard]] virtual ProcessInternalsSnapshot process_internals() const = 0;
    [[nodiscard]] virtual std::optional<RspRemoteThreadId> resolve_remote_thread_id(
        ThreadId local_tid) const = 0;
    [[nodiscard]] virtual Result<std::vector<RspRegisterValue>> read_thread_registers(
        ThreadId local_tid) = 0;
};

class GdbRemoteBackend {
public:
    [[nodiscard]] static Result<std::unique_ptr<IProcessSession>> open_read_only(
        const GdbRemoteOpenOptions& options,
        std::stop_token stop_token = {});

    [[nodiscard]] static Result<std::unique_ptr<IProcessSession>> open_read_only(
        const RemoteEndpointOptions& endpoint,
        std::stop_token stop_token = {});

    [[nodiscard]] static Result<std::unique_ptr<IProcessSession>> open_read_only(
        std::string_view endpoint_spec,
        bool allow_unencrypted_remote_endpoint = false,
        std::stop_token stop_token = {});

    [[nodiscard]] static Result<std::unique_ptr<IProcessSession>> open_read_only(
        std::unique_ptr<IRspTransport> transport,
        const GdbRemoteOpenOptions& options = {},
        std::stop_token stop_token = {});
};

}  // namespace peelf
