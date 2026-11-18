#include <peelf/gdb_remote.hpp>

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
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <limits>
#include <mutex>
#include <unordered_set>
#include <utility>

namespace peelf {

namespace {

[[nodiscard]] constexpr bool is_ascii_space(char ch) noexcept {
    const auto u = static_cast<unsigned char>(ch);
    return u == ' ' || u == '\t' || u == '\r' || u == '\n';
}

[[nodiscard]] constexpr std::string_view trim_ascii(std::string_view sv) noexcept {
    std::size_t start = 0;
    while (start < sv.size() && is_ascii_space(sv[start])) {
        ++start;
    }
    std::size_t end = sv.size();
    while (end > start && is_ascii_space(sv[end - 1])) {
        --end;
    }
    return sv.substr(start, end - start);
}

[[nodiscard]] constexpr char ascii_tolower(char ch) noexcept {
    const auto u = static_cast<unsigned char>(ch);
    if (u >= static_cast<unsigned char>('A') && u <= static_cast<unsigned char>('Z')) {
        return static_cast<char>(u + (static_cast<unsigned char>('a') - static_cast<unsigned char>('A')));
    }
    return ch;
}

[[nodiscard]] std::string to_lower_ascii(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (const char ch : sv) {
        out.push_back(ascii_tolower(ch));
    }
    return out;
}

[[nodiscard]] constexpr bool iequals_ascii(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (ascii_tolower(a[i]) != ascii_tolower(b[i])) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] constexpr std::optional< std::uint8_t > hex_nibble(char ch) noexcept {
    const auto u = static_cast<unsigned char>(ch);
    if (u >= static_cast<unsigned char>('0') && u <= static_cast<unsigned char>('9')) {
        return static_cast<std::uint8_t>(u - static_cast<unsigned char>('0'));
    }
    if (u >= static_cast<unsigned char>('a') && u <= static_cast<unsigned char>('f')) {
        return static_cast<std::uint8_t>(10u + (u - static_cast<unsigned char>('a')));
    }
    if (u >= static_cast<unsigned char>('A') && u <= static_cast<unsigned char>('F')) {
        return static_cast<std::uint8_t>(10u + (u - static_cast<unsigned char>('A')));
    }
    return std::nullopt;
}

[[nodiscard]] std::string format_hex_u64(std::uint64_t value, std::size_t min_digits = 1) {
    static constexpr std::string_view kHex = "0123456789abcdef";
    std::array<char, 16> buf{};
    std::size_t pos = buf.size();
    do {
        --pos;
        buf[pos] = kHex[static_cast<std::size_t>(value & 0xFu)];
        value >>= 4u;
    } while (value != 0u && pos > 0u);
    while (buf.size() - pos < min_digits && pos > 0u) {
        --pos;
        buf[pos] = '0';
    }
    return std::string(buf.data() + pos, buf.size() - pos);
}

[[nodiscard]] std::optional<std::uint64_t> parse_uint64_auto(std::string_view sv) noexcept {
    sv = trim_ascii(sv);
    if (sv.empty()) {
        return std::nullopt;
    }
    int base = 10;
    if (sv.size() > 2 && sv[0] == '0' && (sv[1] == 'x' || sv[1] == 'X')) {
        base = 16;
        sv.remove_prefix(2);
    }
    if (sv.empty()) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    const auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), value, base);
    if (ec != std::errc{} || ptr != sv.data() + sv.size()) {
        return std::nullopt;
    }
    return value;
}

[[nodiscard]] std::optional<std::uint64_t> parse_uint64_hex(std::string_view sv) noexcept {
    sv = trim_ascii(sv);
    if (sv.size() > 2 && sv[0] == '0' && (sv[1] == 'x' || sv[1] == 'X')) {
        sv.remove_prefix(2);
    }
    if (sv.empty()) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    const auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), value, 16);
    if (ec != std::errc{} || ptr != sv.data() + sv.size()) {
        return std::nullopt;
    }
    return value;
}

[[nodiscard]] constexpr bool is_rsp_error_reply(std::string_view reply) noexcept {
    if (reply.empty() || reply.front() != 'E') {
        return false;
    }
    if (reply.size() == 1u || reply.starts_with("E.")) {
        return true;
    }
    return reply.size() == 3u &&
           hex_nibble(reply[1]).has_value() &&
           hex_nibble(reply[2]).has_value();
}

[[nodiscard]] bool is_ipv4_127_literal(std::string_view host) noexcept {
    std::array<unsigned int, 4> octets{};
    std::size_t idx = 0;
    std::size_t pos = 0;
    while (pos < host.size() && idx < 4u) {
        const std::size_t dot = host.find('.', pos);
        const std::string_view part =
            dot == std::string_view::npos ? host.substr(pos) : host.substr(pos, dot - pos);
        if (part.empty() || part.size() > 3u) {
            return false;
        }
        unsigned int val = 0;
        const auto [ptr, ec] = std::from_chars(part.data(), part.data() + part.size(), val, 10);
        if (ec != std::errc{} || ptr != part.data() + part.size() || val > 255u) {
            return false;
        }
        octets[idx] = val;
        ++idx;
        if (dot == std::string_view::npos) {
            pos = host.size();
            break;
        }
        pos = dot + 1u;
        if (pos == host.size()) {
            return false;
        }
    }
    return idx == 4u && pos == host.size() && octets[0] == 127u;
}

[[nodiscard]] bool is_loopback_sockaddr(const sockaddr* addr) noexcept {
    if (addr == nullptr) {
        return false;
    }
    if (addr->sa_family == AF_INET) {
        sockaddr_in sin{};
        std::memcpy(&sin, addr, sizeof(sockaddr_in));
        const std::uint32_t host_ip = ntohl(sin.sin_addr.s_addr);
        return (host_ip & 0xFF00'0000u) == 0x7F00'0000u;
    }
    if (addr->sa_family == AF_INET6) {
        sockaddr_in6 sin6{};
        std::memcpy(&sin6, addr, sizeof(sockaddr_in6));
        if (IN6_IS_ADDR_LOOPBACK(&sin6.sin6_addr)) {
            return true;
        }
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(&sin6.sin6_addr);
        bool prefix_zero = true;
        for (std::size_t i = 0; i < 10u; ++i) {
            if (bytes[i] != 0u) {
                prefix_zero = false;
                break;
            }
        }
        if (prefix_zero && bytes[10] == 0xFFu && bytes[11] == 0xFFu && bytes[12] == 127u) {
            return true;
        }
    }
    return false;
}

#ifdef _WIN32
[[nodiscard]] Result<void> ensure_winsock_initialized() {
    static std::once_flag init_flag;
    static int init_rc = 0;
    std::call_once(init_flag, []() noexcept {
        WSADATA wsa_data{};
        init_rc = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    });
    if (init_rc != 0) {
        return make_error("WSAStartup failed while initializing GDB RSP TCP transport");
    }
    return {};
}

void close_native_socket(TcpRspTransport::NativeSocketHandle s) noexcept {
    if (s != TcpRspTransport::kInvalidSocket) {
        closesocket(static_cast<SOCKET>(s));
    }
}

[[nodiscard]] bool set_nonblocking(TcpRspTransport::NativeSocketHandle s) noexcept {
    u_long mode = 1;
    return ioctlsocket(static_cast<SOCKET>(s), FIONBIO, &mode) == 0;
}
#else
void close_native_socket(TcpRspTransport::NativeSocketHandle s) noexcept {
    if (s != TcpRspTransport::kInvalidSocket) {
        ::close(s);
    }
}

[[nodiscard]] bool set_nonblocking(TcpRspTransport::NativeSocketHandle s) noexcept {
    const int flags = ::fcntl(s, F_GETFL, 0);
    if (flags == -1) {
        return false;
    }
    return ::fcntl(s, F_SETFL, flags | O_NONBLOCK) == 0;
}
#endif

}  // namespace

// ---------------------------------------------------------------------------
// Endpoint parsing & loopback policy
// ---------------------------------------------------------------------------

bool is_loopback_endpoint_host(std::string_view host) noexcept {
    host = trim_ascii(host);
    if (host.size() >= 2u && host.front() == '[' && host.back() == ']') {
        host = host.substr(1u, host.size() - 2u);
    }
    if (host.empty()) {
        return false;
    }
    if (iequals_ascii(host, "localhost") || host == "::1" || host == "0:0:0:0:0:0:0:1") {
        return true;
    }
    if (is_ipv4_127_literal(host)) {
        return true;
    }
    constexpr std::string_view kV4MappedPrefix = "::ffff:";
    if (host.size() > kV4MappedPrefix.size() &&
        iequals_ascii(host.substr(0, kV4MappedPrefix.size()), kV4MappedPrefix)) {
        return is_ipv4_127_literal(host.substr(kV4MappedPrefix.size()));
    }
    return false;
}

Result<RemoteEndpointOptions> parse_gdb_remote_endpoint(
    std::string_view endpoint,
    RemoteEndpointOptions defaults) {
    endpoint = trim_ascii(endpoint);
    if (endpoint.empty()) {
        return make_error("GDB remote endpoint string cannot be empty");
    }

    for (const std::string_view prefix : {"tcp:", "tcp4:", "tcp6:"}) {
        if (endpoint.size() > prefix.size() &&
            iequals_ascii(endpoint.substr(0, prefix.size()), prefix)) {
            endpoint.remove_prefix(prefix.size());
            break;
        }
    }

    if (endpoint.find("://") != std::string_view::npos) {
        return make_error("Unsupported URI scheme in GDB remote endpoint; expected host:port");
    }

    std::string_view host_part{};
    std::string_view port_part{};

    if (endpoint.front() == '[') {
        const std::size_t close_bracket = endpoint.find(']');
        if (close_bracket == std::string_view::npos) {
            return make_error("Missing closing ']' in IPv6 GDB remote endpoint");
        }
        host_part = endpoint.substr(1u, close_bracket - 1u);
        if (host_part.empty()) {
            return make_error("Empty IPv6 address in GDB remote endpoint");
        }
        const std::string_view remainder = endpoint.substr(close_bracket + 1u);
        if (remainder.size() < 2u || remainder.front() != ':') {
            return make_error("Expected ':port' after bracketed IPv6 address");
        }
        port_part = remainder.substr(1u);
    } else {
        const std::size_t first_colon = endpoint.find(':');
        const std::size_t last_colon = endpoint.rfind(':');
        if (first_colon == std::string_view::npos) {
            return make_error("Missing ':port' in GDB remote endpoint");
        }
        if (first_colon != last_colon) {
            return make_error("Unbracketed IPv6 address in GDB remote endpoint; wrap host in '[...]'");
        }
        host_part = endpoint.substr(0, first_colon);
        port_part = endpoint.substr(first_colon + 1u);
        if (host_part.empty()) {
            host_part = "127.0.0.1";
        }
    }

    if (port_part.empty()) {
        return make_error("Empty port in GDB remote endpoint");
    }
    std::uint32_t parsed_port = 0;
    const auto [ptr, ec] =
        std::from_chars(port_part.data(), port_part.data() + port_part.size(), parsed_port, 10);
    if (ec != std::errc{} || ptr != port_part.data() + port_part.size() ||
        parsed_port == 0u || parsed_port > 65535u) {
        return make_error("Invalid TCP port in GDB remote endpoint");
    }

    defaults.host = std::string(host_part);
    defaults.port = static_cast<std::uint16_t>(parsed_port);
    return defaults;
}

// ---------------------------------------------------------------------------
// TcpRspTransport
// ---------------------------------------------------------------------------

TcpRspTransport::TcpRspTransport(NativeSocketHandle handle, std::string endpoint_desc) noexcept
    : socket_(handle), endpoint_desc_(std::move(endpoint_desc)) {}

TcpRspTransport::TcpRspTransport(TcpRspTransport&& other) noexcept
    : socket_(std::exchange(other.socket_, kInvalidSocket)),
      endpoint_desc_(std::move(other.endpoint_desc_)) {}

TcpRspTransport& TcpRspTransport::operator=(TcpRspTransport&& other) noexcept {
    if (this != &other) {
        close();
        socket_ = std::exchange(other.socket_, kInvalidSocket);
        endpoint_desc_ = std::move(other.endpoint_desc_);
    }
    return *this;
}

TcpRspTransport::~TcpRspTransport() noexcept {
    close();
}

bool TcpRspTransport::is_open() const noexcept {
    return socket_ != kInvalidSocket;
}

void TcpRspTransport::close() noexcept {
    const NativeSocketHandle prev = std::exchange(socket_, kInvalidSocket);
    close_native_socket(prev);
}

Result<std::unique_ptr<TcpRspTransport>> TcpRspTransport::connect(
    const RemoteEndpointOptions& options,
    std::stop_token stop_token) {
    if (stop_token.stop_requested()) {
        return make_error("GDB RSP connection cancelled before connect");
    }
    std::string clean_host(trim_ascii(options.host));
    if (clean_host.size() >= 2u && clean_host.front() == '[' && clean_host.back() == ']') {
        clean_host = clean_host.substr(1u, clean_host.size() - 2u);
    }
    if (clean_host.empty() || options.port == 0u) {
        return make_error("GDB RSP endpoint requires a non-empty host and non-zero port");
    }

    if (!options.allow_unencrypted_remote_endpoint && !is_loopback_endpoint_host(clean_host)) {
        return make_error(
            "Refusing unencrypted GDB RSP connection to non-loopback endpoint '" + clean_host +
            "'; set RemoteEndpointOptions::allow_unencrypted_remote_endpoint = true to opt in");
    }

#ifdef _WIN32
    if (auto wsa_res = ensure_winsock_initialized(); !wsa_res) {
        return std::unexpected(wsa_res.error());
    }
#endif

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    const std::string port_str = std::to_string(options.port);
    addrinfo* raw_addrs = nullptr;
    const int gai_rc = ::getaddrinfo(clean_host.c_str(), port_str.c_str(), &hints, &raw_addrs);
    if (gai_rc != 0 || raw_addrs == nullptr) {
        return make_error("Failed to resolve GDB RSP endpoint '" + clean_host + ":" + port_str + "'");
    }
    const std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> addr_guard(raw_addrs, &::freeaddrinfo);

    bool saw_rejected_non_loopback = false;
    std::string last_connect_err = "Unable to connect to GDB RSP endpoint";
    const auto connect_deadline =
        std::chrono::steady_clock::now() +
        std::max(options.connect_timeout, std::chrono::milliseconds{1});

    for (const addrinfo* ai = addr_guard.get(); ai != nullptr; ai = ai->ai_next) {
        if (stop_token.stop_requested()) {
            return make_error("GDB RSP connection cancelled");
        }
        if (!options.allow_unencrypted_remote_endpoint && !is_loopback_sockaddr(ai->ai_addr)) {
            saw_rejected_non_loopback = true;
            continue;
        }

#ifdef _WIN32
        const SOCKET raw_sock = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (raw_sock == INVALID_SOCKET) {
            continue;
        }
        const auto handle = static_cast<NativeSocketHandle>(raw_sock);
#else
        const int handle = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (handle < 0) {
            continue;
        }
#endif
        TcpRspTransport candidate(
            handle,
            (clean_host.find(':') != std::string::npos ? ("[" + clean_host + "]") : clean_host) +
                ":" + port_str);

        if (!set_nonblocking(handle)) {
            last_connect_err = "Failed to configure non-blocking GDB RSP socket";
            continue;
        }

        if (options.enable_tcp_nodelay) {
            const int one = 1;
#ifdef _WIN32
            (void)::setsockopt(
                static_cast<SOCKET>(handle),
                IPPROTO_TCP,
                TCP_NODELAY,
                reinterpret_cast<const char*>(&one),
                static_cast<int>(sizeof(one)));
#else
            (void)::setsockopt(
                handle,
                IPPROTO_TCP,
                TCP_NODELAY,
                &one,
                static_cast<socklen_t>(sizeof(one)));
#endif
        }

#ifdef _WIN32
        const int rc = ::connect(
            static_cast<SOCKET>(handle), ai->ai_addr, static_cast<int>(ai->ai_addrlen));
        const int err = (rc == 0) ? 0 : ::WSAGetLastError();
        const bool in_progress = (rc != 0) && (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS);
#else
        const int rc = ::connect(handle, ai->ai_addr, ai->ai_addrlen);
        const int err = (rc == 0) ? 0 : errno;
        const bool in_progress = (rc != 0) && (err == EINPROGRESS || err == EINTR);
#endif
        if (rc == 0) {
            return std::make_unique<TcpRspTransport>(std::move(candidate));
        }
        if (!in_progress) {
            last_connect_err = "TCP connect failed for GDB RSP endpoint";
            continue;
        }

        bool connected = false;
        while (std::chrono::steady_clock::now() < connect_deadline) {
            if (stop_token.stop_requested()) {
                return make_error("GDB RSP connection cancelled during connect");
            }
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                connect_deadline - std::chrono::steady_clock::now());
            const int slice_ms = static_cast<int>(std::clamp<std::int64_t>(remaining.count(), 1, 50));

#ifdef _WIN32
            WSAPOLLFD pfd{};
            pfd.fd = static_cast<SOCKET>(handle);
            pfd.events = POLLWRNORM;
            const int prc = ::WSAPoll(&pfd, 1, slice_ms);
#else
            pollfd pfd{};
            pfd.fd = handle;
            pfd.events = POLLOUT;
            const int prc = ::poll(&pfd, 1, slice_ms);
#endif
            if (prc == 0) {
                continue;
            }
            if (prc < 0) {
#ifndef _WIN32
                if (errno == EINTR) {
                    continue;
                }
#endif
                last_connect_err = "Socket poll failed while connecting to GDB RSP endpoint";
                break;
            }

            int sock_err = 0;
#ifdef _WIN32
            int err_len = static_cast<int>(sizeof(sock_err));
            const int opt_rc = ::getsockopt(
                static_cast<SOCKET>(handle),
                SOL_SOCKET,
                SO_ERROR,
                reinterpret_cast<char*>(&sock_err),
                &err_len);
#else
            socklen_t err_len = sizeof(sock_err);
            const int opt_rc = ::getsockopt(handle, SOL_SOCKET, SO_ERROR, &sock_err, &err_len);
#endif
            if (opt_rc == 0 && sock_err == 0) {
                connected = true;
            } else {
                last_connect_err = "GDB RSP TCP connection refused or unreachable";
            }
            break;
        }

        if (connected) {
            return std::make_unique<TcpRspTransport>(std::move(candidate));
        }
        if (std::chrono::steady_clock::now() >= connect_deadline) {
            last_connect_err = "Timed out connecting to GDB RSP endpoint";
            break;
        }
    }

    if (saw_rejected_non_loopback) {
        return make_error(
            "Refusing unencrypted GDB RSP connection because '" + clean_host +
            "' resolved to a non-loopback address");
    }
    return make_error(last_connect_err + " '" + clean_host + ":" + port_str + "'");
}

Result<RspReadOutcome> TcpRspTransport::read_some(
    std::span<std::uint8_t> buffer,
    std::chrono::milliseconds timeout,
    std::stop_token stop_token) {
    if (!is_open()) {
        return make_error("GDB RSP socket transport is closed");
    }
    if (buffer.empty()) {
        return RspReadOutcome{RspIoStatus::Ok, 0u};
    }

    const auto deadline =
        std::chrono::steady_clock::now() + std::max(timeout, std::chrono::milliseconds{0});

    for (;;) {
        if (stop_token.stop_requested()) {
            return RspReadOutcome{RspIoStatus::Cancelled, 0u};
        }

        const int capped_len = static_cast<int>(
            std::min<std::size_t>(buffer.size(), static_cast<std::size_t>(std::numeric_limits<int>::max())));
#ifdef _WIN32
        const int n = ::recv(
            static_cast<SOCKET>(socket_),
            reinterpret_cast<char*>(buffer.data()),
            capped_len,
            0);
        if (n > 0) {
            return RspReadOutcome{RspIoStatus::Ok, static_cast<std::size_t>(n)};
        }
        if (n == 0) {
            return RspReadOutcome{RspIoStatus::EndOfStream, 0u};
        }
        const int err = ::WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
            return make_error("GDB RSP socket receive failed");
        }
#else
        const ssize_t n = ::recv(socket_, buffer.data(), static_cast<std::size_t>(capped_len), 0);
        if (n > 0) {
            return RspReadOutcome{RspIoStatus::Ok, static_cast<std::size_t>(n)};
        }
        if (n == 0) {
            return RspReadOutcome{RspIoStatus::EndOfStream, 0u};
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return make_error("GDB RSP socket receive failed");
        }
#endif

        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            return RspReadOutcome{RspIoStatus::Timeout, 0u};
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        const int slice_ms = static_cast<int>(std::clamp<std::int64_t>(remaining.count(), 1, 50));

#ifdef _WIN32
        WSAPOLLFD pfd{};
        pfd.fd = static_cast<SOCKET>(socket_);
        pfd.events = POLLRDNORM;
        const int prc = ::WSAPoll(&pfd, 1, slice_ms);
#else
        pollfd pfd{};
        pfd.fd = socket_;
        pfd.events = POLLIN;
        const int prc = ::poll(&pfd, 1, slice_ms);
#endif
        if (prc < 0) {
#ifndef _WIN32
            if (errno == EINTR) {
                continue;
            }
#endif
            return make_error("Socket poll failed while reading GDB RSP stream");
        }
    }
}

Result<void> TcpRspTransport::write_all(
    std::span<const std::uint8_t> data,
    std::chrono::milliseconds timeout,
    std::stop_token stop_token) {
    if (!is_open()) {
        return make_error("GDB RSP socket transport is closed");
    }
    const auto deadline =
        std::chrono::steady_clock::now() + std::max(timeout, std::chrono::milliseconds{1});

    std::size_t total_sent = 0;
    while (total_sent < data.size()) {
        if (stop_token.stop_requested()) {
            return make_error("GDB RSP write cancelled");
        }
        const std::size_t remaining_bytes = data.size() - total_sent;
        const int chunk_len = static_cast<int>(std::min<std::size_t>(
            remaining_bytes, static_cast<std::size_t>(std::numeric_limits<int>::max())));

#ifdef _WIN32
        const int sent = ::send(
            static_cast<SOCKET>(socket_),
            reinterpret_cast<const char*>(data.data() + total_sent),
            chunk_len,
            0);
        if (sent > 0) {
            total_sent += static_cast<std::size_t>(sent);
            continue;
        }
        const int err = ::WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
            return make_error("GDB RSP socket send failed");
        }
#else
        int send_flags = 0;
#ifdef MSG_NOSIGNAL
        send_flags |= MSG_NOSIGNAL;
#endif
        const ssize_t sent = ::send(
            socket_, data.data() + total_sent, static_cast<std::size_t>(chunk_len), send_flags);
        if (sent > 0) {
            total_sent += static_cast<std::size_t>(sent);
            continue;
        }
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            return make_error("GDB RSP socket send failed");
        }
#endif

        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            return make_error("Timed out writing GDB RSP packet");
        }
        const auto wait_rem =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        const int slice_ms = static_cast<int>(std::clamp<std::int64_t>(wait_rem.count(), 1, 50));

#ifdef _WIN32
        WSAPOLLFD pfd{};
        pfd.fd = static_cast<SOCKET>(socket_);
        pfd.events = POLLWRNORM;
        const int prc = ::WSAPoll(&pfd, 1, slice_ms);
#else
        pollfd pfd{};
        pfd.fd = socket_;
        pfd.events = POLLOUT;
        const int prc = ::poll(&pfd, 1, slice_ms);
#endif
        if (prc < 0) {
#ifndef _WIN32
            if (errno == EINTR) {
                continue;
            }
#endif
            return make_error("Socket poll failed while writing GDB RSP stream");
        }
    }
    return {};
}

// ---------------------------------------------------------------------------
// RSP framing, escaping, RLE, checksums, & read-only guard
// ---------------------------------------------------------------------------

std::uint8_t compute_rsp_checksum(std::string_view wire_payload) noexcept {
    std::uint8_t sum = 0;
    for (const char ch : wire_payload) {
        sum = static_cast<std::uint8_t>(sum + static_cast<std::uint8_t>(ch));
    }
    return sum;
}

std::string rsp_escape_payload(std::string_view raw_payload) {
    std::string out;
    out.reserve(raw_payload.size());
    for (const char ch : raw_payload) {
        const auto byte = static_cast<std::uint8_t>(ch);
        if (byte == 0x23u || byte == 0x24u || byte == 0x2Au || byte == 0x7Du) {
            out.push_back('}');
            out.push_back(static_cast<char>(byte ^ 0x20u));
        } else {
            out.push_back(ch);
        }
    }
    return out;
}

std::string rsp_encode_frame(std::string_view raw_payload) {
    static constexpr std::string_view kHex = "0123456789abcdef";
    const std::string escaped = rsp_escape_payload(raw_payload);
    const std::uint8_t csum = compute_rsp_checksum(escaped);
    std::string frame;
    frame.reserve(escaped.size() + 4u);
    frame.push_back('$');
    frame.append(escaped);
    frame.push_back('#');
    frame.push_back(kHex[static_cast<std::size_t>((csum >> 4u) & 0xFu)]);
    frame.push_back(kHex[static_cast<std::size_t>(csum & 0xFu)]);
    return frame;
}

Result<std::string> rsp_decode_wire_payload(
    std::string_view wire_payload,
    std::size_t max_decoded_bytes) {
    std::string out;
    out.reserve(std::min(wire_payload.size(), max_decoded_bytes));

    std::size_t i = 0;
    while (i < wire_payload.size()) {
        const auto ch = static_cast<std::uint8_t>(wire_payload[i]);
        if (ch == 0x7Du) {  // '}'
            if (i + 1u >= wire_payload.size()) {
                return make_error("Truncated '}' escape sequence in GDB RSP packet");
            }
            if (out.size() >= max_decoded_bytes) {
                return make_error("Decoded GDB RSP payload exceeds maximum size bound");
            }
            const auto next = static_cast<std::uint8_t>(wire_payload[i + 1u]);
            out.push_back(static_cast<char>(next ^ 0x20u));
            i += 2u;
            continue;
        }
        if (ch == 0x2Au) {  // '*' RLE operator
            if (out.empty() || i + 1u >= wire_payload.size()) {
                return make_error("Malformed '*' run-length encoding in GDB RSP packet");
            }
            const auto repeat_byte = static_cast<std::uint8_t>(wire_payload[i + 1u]);
            if (repeat_byte < 32u || repeat_byte > 126u ||
                repeat_byte == static_cast<std::uint8_t>('$') ||
                repeat_byte == static_cast<std::uint8_t>('#')) {
                return make_error("Invalid RLE repeat count byte in GDB RSP packet");
            }
            const std::size_t repeat_count = static_cast<std::size_t>(repeat_byte - 29u);
            if (repeat_count > max_decoded_bytes - out.size()) {
                return make_error("GDB RSP RLE expansion exceeds maximum decoded payload bound");
            }
            out.append(repeat_count, out.back());
            i += 2u;
            continue;
        }
        if (out.size() >= max_decoded_bytes) {
            return make_error("Decoded GDB RSP payload exceeds maximum size bound");
        }
        out.push_back(static_cast<char>(ch));
        ++i;
    }
    return out;
}

bool is_mutating_rsp_packet(std::string_view payload) noexcept {
    if (payload.empty()) {
        return false;
    }
    switch (payload.front()) {
        case 'M':  // Write hex memory
        case 'X':  // Write binary memory
        case 'G':  // Write general registers
        case 'P':  // Write single register
        case 'Z':  // Insert breakpoint / watchpoint
        case 'z':  // Remove breakpoint / watchpoint
        case 'k':  // Kill target
        case 'c':  // Continue
        case 'C':  // Continue with signal
        case 's':  // Single-step
        case 'S':  // Single-step with signal
        case 'R':  // Restart
        case 'D':  // Detach / alter attach state
        case '!':  // Extended mode
        case 'F':  // File-I/O reply
        case 'I':  // Signal + cycle step
        case 'i':  // Cycle step
        case 't':  // Backward search / trace
            return true;
        case 'H':
            // Only Hg<thread> is permitted in read-only mode; Hc<thread> alters step/continue focus.
            return payload.size() < 2u || payload[1] != 'g';
        case 'Q':
            // QStartNoAckMode is pure transport framing; all other Q* packets mutate stub/target state.
            return payload != "QStartNoAckMode";
        case 'v':
            return payload.starts_with("vKill") ||
                   payload.starts_with("vCont") ||
                   payload.starts_with("vRun") ||
                   payload.starts_with("vAttach") ||
                   payload.starts_with("vFlash") ||
                   payload.starts_with("vFile:") ||
                   payload.starts_with("vStopped");
        default:
            return false;
    }
}

RspCapabilities parse_qsupported_reply(
    std::string_view reply,
    std::size_t max_client_packet_size) {
    RspCapabilities caps{};
    std::size_t pos = 0;
    while (pos <= reply.size()) {
        const std::size_t semi = reply.find(';', pos);
        const std::string_view token = trim_ascii(
            semi == std::string_view::npos ? reply.substr(pos) : reply.substr(pos, semi - pos));
        if (!token.empty()) {
            caps.raw_features.emplace_back(token);
            if (token.starts_with("PacketSize=")) {
                const std::string_view hex_sz = token.substr(std::string_view{"PacketSize="}.size());
                if (const auto parsed = parse_uint64_hex(hex_sz);
                    parsed.has_value() && *parsed > 0u) {
                    const std::uint64_t effective_client_max =
                        std::max<std::uint64_t>(64u, static_cast<std::uint64_t>(max_client_packet_size));
                    const auto clamped = static_cast<std::size_t>(
                        std::clamp<std::uint64_t>(*parsed, 64u, effective_client_max));
                    caps.packet_size = clamped;
                }
            } else if (token == "QStartNoAckMode+") {
                caps.no_ack_mode_supported = true;
            } else if (token == "multiprocess+") {
                caps.multiprocess = true;
            } else if (token == "qXfer:features:read+") {
                caps.qxfer_features_read = true;
            } else if (token == "qXfer:memory-map:read+") {
                caps.qxfer_memory_map_read = true;
            } else if (token == "qXfer:libraries-svr4:read+") {
                caps.qxfer_libraries_svr4_read = true;
            } else if (token == "qXfer:libraries:read+") {
                caps.qxfer_libraries_read = true;
            } else if (token == "qXfer:auxv:read+") {
                caps.qxfer_auxv_read = true;
            }
        }
        if (semi == std::string_view::npos) {
            break;
        }
        pos = semi + 1u;
    }
    return caps;
}

// ---------------------------------------------------------------------------
// Bounded, non-networked XML parser (zero external entity / DTD resolution)
// ---------------------------------------------------------------------------

namespace {

struct XmlAttribute {
    std::string name{};
    std::string value{};
};

struct XmlElement {
    std::string name{};
    std::vector<XmlAttribute> attributes{};
    std::string text{};
    std::vector<XmlElement> children{};

    [[nodiscard]] std::optional<std::string_view> attr(std::string_view key) const noexcept {
        for (const auto& a : attributes) {
            if (a.name == key) {
                return a.value;
            }
        }
        return std::nullopt;
    }
};

[[nodiscard]] constexpr bool is_xml_name_char(char ch) noexcept {
    const auto u = static_cast<unsigned char>(ch);
    return (u >= static_cast<unsigned char>('a') && u <= static_cast<unsigned char>('z')) ||
           (u >= static_cast<unsigned char>('A') && u <= static_cast<unsigned char>('Z')) ||
           (u >= static_cast<unsigned char>('0') && u <= static_cast<unsigned char>('9')) ||
           u == '_' || u == '-' || u == ':' || u == '.';
}

[[nodiscard]] Result<std::string> unescape_xml_entities(std::string_view raw) {
    std::string out;
    out.reserve(raw.size());
    std::size_t i = 0;
    while (i < raw.size()) {
        if (raw[i] != '&') {
            out.push_back(raw[i]);
            ++i;
            continue;
        }
        const std::size_t semi = raw.find(';', i + 1u);
        if (semi == std::string_view::npos || semi - i > 16u) {
            return make_error("Malformed XML entity reference in GDB RSP XML annex");
        }
        const std::string_view ent = raw.substr(i + 1u, semi - (i + 1u));
        if (ent == "lt") {
            out.push_back('<');
        } else if (ent == "gt") {
            out.push_back('>');
        } else if (ent == "amp") {
            out.push_back('&');
        } else if (ent == "quot") {
            out.push_back('"');
        } else if (ent == "apos") {
            out.push_back('\'');
        } else if (ent.size() >= 2u && ent.front() == '#') {
            std::optional<std::uint64_t> cp{};
            if (ent[1] == 'x' || ent[1] == 'X') {
                cp = parse_uint64_hex(ent.substr(2u));
            } else {
                cp = parse_uint64_auto(ent.substr(1u));
            }
            if (!cp.has_value() || *cp == 0u || *cp > 0x7Fu) {
                return make_error("Unsupported numeric XML character reference in GDB RSP annex");
            }
            out.push_back(static_cast<char>(*cp));
        } else {
            return make_error("Disallowed custom/external XML entity '&" + std::string(ent) + ";'");
        }
        i = semi + 1u;
    }
    return out;
}

class BoundedXmlParser {
public:
    explicit BoundedXmlParser(std::string_view input) noexcept : src_(input) {}

    [[nodiscard]] Result<XmlElement> parse_document() {
        constexpr std::size_t kMaxInputBytes = 16u * 1024u * 1024u;
        if (src_.size() > kMaxInputBytes) {
            return make_error("GDB RSP XML annex exceeds 16 MiB bound");
        }

        std::optional<XmlElement> root{};
        while (pos_ < src_.size()) {
            skip_ws();
            if (pos_ >= src_.size()) {
                break;
            }
            if (src_[pos_] != '<') {
                return make_error("Unexpected text outside root element in GDB RSP XML");
            }
            if (try_skip_Trivia_or_doctype()) {
                if (!error_.empty()) {
                    return make_error(error_);
                }
                continue;
            }
            if (root.has_value()) {
                return make_error("Multiple root elements in GDB RSP XML");
            }
            auto elem = parse_element(0u);
            if (!elem) {
                return elem;
            }
            root = std::move(*elem);
        }
        if (!root.has_value()) {
            return make_error("Empty GDB RSP XML document");
        }
        return std::move(*root);
    }

private:
    void skip_ws() noexcept {
        while (pos_ < src_.size() && is_ascii_space(src_[pos_])) {
            ++pos_;
        }
    }

    [[nodiscard]] bool starts_with(std::string_view prefix) const noexcept {
        return src_.substr(pos_).starts_with(prefix);
    }

    [[nodiscard]] bool try_skip_Trivia_or_doctype() {
        if (starts_with("<!--")) {
            const std::size_t end = src_.find("-->", pos_ + 4u);
            if (end == std::string_view::npos) {
                error_ = "Unterminated XML comment in GDB RSP annex";
                return true;
            }
            pos_ = end + 3u;
            return true;
        }
        if (starts_with("<?")) {
            const std::size_t end = src_.find("?>", pos_ + 2u);
            if (end == std::string_view::npos) {
                error_ = "Unterminated XML processing instruction in GDB RSP annex";
                return true;
            }
            pos_ = end + 2u;
            return true;
        }
        if (starts_with("<!DOCTYPE") || starts_with("<!doctype")) {
            // Skip DOCTYPE header without ever loading external SYSTEM/PUBLIC DTDs;
            // explicitly forbid <!ENTITY declarations inside internal subsets.
            pos_ += 9u;
            int bracket_depth = 0;
            while (pos_ < src_.size()) {
                if (starts_with("<!ENTITY") || starts_with("<!entity")) {
                    error_ = "XML <!ENTITY> declarations are forbidden in GDB RSP annexes";
                    return true;
                }
                const char ch = src_[pos_];
                if (ch == '"' || ch == '\'') {
                    const std::size_t close_q = src_.find(ch, pos_ + 1u);
                    if (close_q == std::string_view::npos) {
                        error_ = "Unterminated quote in XML DOCTYPE";
                        return true;
                    }
                    pos_ = close_q + 1u;
                    continue;
                }
                if (ch == '[') {
                    ++bracket_depth;
                } else if (ch == ']') {
                    if (bracket_depth <= 0) {
                        error_ = "Malformed internal subset in XML DOCTYPE";
                        return true;
                    }
                    --bracket_depth;
                } else if (ch == '>' && bracket_depth == 0) {
                    ++pos_;
                    return true;
                }
                ++pos_;
            }
            error_ = "Unterminated XML DOCTYPE in GDB RSP annex";
            return true;
        }
        return false;
    }

    [[nodiscard]] Result<std::string_view> read_name() {
        const std::size_t start = pos_;
        while (pos_ < src_.size() && is_xml_name_char(src_[pos_])) {
            ++pos_;
        }
        if (pos_ == start) {
            return make_error("Expected XML element or attribute name in GDB RSP annex");
        }
        return src_.substr(start, pos_ - start);
    }

    [[nodiscard]] Result<XmlElement> parse_element(std::size_t depth) {
        constexpr std::size_t kMaxDepth = 32u;
        constexpr std::size_t kMaxElements = 16384u;
        if (depth > kMaxDepth) {
            return make_error("GDB RSP XML exceeds maximum element nesting depth");
        }
        ++element_count_;
        if (element_count_ > kMaxElements) {
            return make_error("GDB RSP XML exceeds maximum element count");
        }

        if (pos_ >= src_.size() || src_[pos_] != '<') {
            return make_error("Expected '<' at XML element start");
        }
        ++pos_;  // consume '<'

        auto tag_name = read_name();
        if (!tag_name) {
            return std::unexpected(tag_name.error());
        }

        XmlElement elem{};
        elem.name = std::string(*tag_name);

        bool self_closing = false;
        for (;;) {
            skip_ws();
            if (pos_ >= src_.size()) {
                return make_error("Unterminated XML start tag '<" + elem.name + ">'");
            }
            if (starts_with("/>")) {
                pos_ += 2u;
                self_closing = true;
                break;
            }
            if (src_[pos_] == '>') {
                ++pos_;
                break;
            }

            auto attr_name = read_name();
            if (!attr_name) {
                return std::unexpected(attr_name.error());
            }
            skip_ws();
            if (pos_ >= src_.size() || src_[pos_] != '=') {
                return make_error("Expected '=' after XML attribute '" + std::string(*attr_name) + "'");
            }
            ++pos_;
            skip_ws();
            if (pos_ >= src_.size() || (src_[pos_] != '"' && src_[pos_] != '\'')) {
                return make_error("Expected quoted value for XML attribute '" + std::string(*attr_name) + "'");
            }
            const char quote = src_[pos_];
            ++pos_;
            const std::size_t val_start = pos_;
            const std::size_t val_end = src_.find(quote, val_start);
            if (val_end == std::string_view::npos) {
                return make_error("Unterminated attribute value in '<" + elem.name + ">'");
            }
            auto decoded_val = unescape_xml_entities(src_.substr(val_start, val_end - val_start));
            if (!decoded_val) {
                return std::unexpected(decoded_val.error());
            }
            elem.attributes.push_back(XmlAttribute{
                .name = std::string(*attr_name),
                .value = std::move(*decoded_val),
            });
            pos_ = val_end + 1u;
        }

        if (self_closing) {
            return elem;
        }

        while (pos_ < src_.size()) {
            if (src_[pos_] != '<') {
                const std::size_t next_lt = src_.find('<', pos_);
                const std::size_t end_text =
                    next_lt == std::string_view::npos ? src_.size() : next_lt;
                auto chunk = unescape_xml_entities(src_.substr(pos_, end_text - pos_));
                if (!chunk) {
                    return std::unexpected(chunk.error());
                }
                elem.text.append(*chunk);
                pos_ = end_text;
                continue;
            }

            if (starts_with("<![CDATA[")) {
                const std::size_t end_cdata = src_.find("]]>", pos_ + 9u);
                if (end_cdata == std::string_view::npos) {
                    return make_error("Unterminated CDATA section in GDB RSP XML");
                }
                elem.text.append(src_.substr(pos_ + 9u, end_cdata - (pos_ + 9u)));
                pos_ = end_cdata + 3u;
                continue;
            }

            if (starts_with("<!--")) {
                if (try_skip_Trivia_or_doctype() && !error_.empty()) {
                    return make_error(error_);
                }
                continue;
            }

            if (starts_with("</")) {
                pos_ += 2u;
                auto close_name = read_name();
                if (!close_name) {
                    return std::unexpected(close_name.error());
                }
                skip_ws();
                if (pos_ >= src_.size() || src_[pos_] != '>') {
                    return make_error("Malformed closing tag '</" + std::string(*close_name) + ">'");
                }
                ++pos_;
                if (*close_name != elem.name) {
                    return make_error(
                        "Mismatched XML closing tag '</" + std::string(*close_name) +
                        ">' for '<" + elem.name + ">'");
                }
                elem.text = std::string(trim_ascii(elem.text));
                return elem;
            }

            if (starts_with("<!")) {
                return make_error("Unexpected XML declaration inside '<" + elem.name + ">'");
            }

            auto child = parse_element(depth + 1u);
            if (!child) {
                return child;
            }
            elem.children.push_back(std::move(*child));
        }

        return make_error("Missing closing tag for '<" + elem.name + ">'");
    }

    std::string_view src_{};
    std::size_t pos_{0};
    std::size_t element_count_{0};
    std::string error_{};
};

[[nodiscard]] bool is_xi_include_tag(std::string_view tag_name) noexcept {
    if (tag_name == "include") {
        return true;
    }
    const std::size_t colon = tag_name.rfind(':');
    return colon != std::string_view::npos && tag_name.substr(colon + 1u) == "include";
}

[[nodiscard]] Result<void> validate_annex_href(std::string_view href) {
    if (href.empty()) {
        return make_error("Empty href in <xi:include> within target.xml");
    }
    if (href.find("://") != std::string_view::npos || href.front() == '/' ||
        href.front() == '\\' || href.find('\\') != std::string_view::npos ||
        href.find(':') != std::string_view::npos) {
        return make_error("Rejected external or absolute <xi:include href='" + std::string(href) + "'>");
    }
    if (href.find("..") != std::string_view::npos) {
        return make_error("Rejected parent-traversal <xi:include href='" + std::string(href) + "'>");
    }
    return {};
}

void apply_architecture_string(std::string_view raw_arch, RspTargetDescription& desc) {
    const std::string lower = to_lower_ascii(trim_ascii(raw_arch));
    if (lower.empty()) {
        return;
    }

    Endianness default_endian = Endianness::Little;
    if (lower.find("x86-64") != std::string::npos || lower.find("x86_64") != std::string::npos ||
        lower == "amd64") {
        desc.architecture = Architecture::X86_64;
        desc.address_width = AddressWidth::Bits64;
    } else if (lower.starts_with("i386") || lower == "i8086" || lower == "x86") {
        desc.architecture = Architecture::X86;
        desc.address_width = AddressWidth::Bits32;
    } else if (lower.starts_with("aarch64") || lower == "arm64") {
        desc.architecture = Architecture::ARM64;
        desc.address_width =
            lower.find("ilp32") != std::string::npos ? AddressWidth::Bits32 : AddressWidth::Bits64;
        if (lower.find("_be") != std::string::npos || lower.ends_with("be")) {
            default_endian = Endianness::Big;
        }
    } else if (lower.starts_with("arm") || lower.starts_with("xscale") ||
               lower.starts_with("iwmmxt")) {
        desc.architecture = Architecture::ARM;
        desc.address_width = AddressWidth::Bits32;
        if (lower.find("eb") != std::string::npos || lower.find("be") != std::string::npos) {
            default_endian = Endianness::Big;
        }
    } else if (lower.find("rv64") != std::string::npos || lower == "riscv64") {
        desc.architecture = Architecture::RISCV64;
        desc.address_width = AddressWidth::Bits64;
    } else if (lower.find("rv32") != std::string::npos || lower == "riscv32" ||
               lower == "riscv") {
        desc.architecture = Architecture::RISCV32;
        desc.address_width = AddressWidth::Bits32;
    } else if (lower.find("powerpc:common64") != std::string::npos ||
               lower.starts_with("powerpc64") || lower.starts_with("ppc64")) {
        desc.architecture = Architecture::PowerPC64;
        desc.address_width = AddressWidth::Bits64;
        default_endian =
            lower.ends_with("le") ? Endianness::Little : Endianness::Big;
    } else if (lower.starts_with("powerpc") || lower.starts_with("ppc") ||
               lower.starts_with("rs6000")) {
        desc.architecture = Architecture::PowerPC;
        desc.address_width = AddressWidth::Bits32;
        default_endian =
            lower.ends_with("le") ? Endianness::Little : Endianness::Big;
    } else if (lower.starts_with("mips")) {
        const bool is_64 = lower.find("64") != std::string::npos ||
                           lower.find("4000") != std::string::npos ||
                           lower.find("8000") != std::string::npos;
        desc.architecture = is_64 ? Architecture::MIPS64 : Architecture::MIPS32;
        desc.address_width = is_64 ? AddressWidth::Bits64 : AddressWidth::Bits32;
        default_endian =
            lower.find("el") != std::string::npos ? Endianness::Little : Endianness::Big;
    }

    if (!desc.explicit_endianness) {
        desc.endianness = default_endian;
    }
}

void apply_osabi_string(std::string_view raw_osabi, RspTargetDescription& desc) {
    const std::string lower = to_lower_ascii(trim_ascii(raw_osabi));
    if (lower.find("linux") != std::string::npos) {
        desc.os = OsKind::Linux;
        desc.abi = AbiKind::GnuLinux;
    } else if (lower.find("windows") != std::string::npos ||
               lower.find("cygwin") != std::string::npos ||
               lower.find("mingw") != std::string::npos) {
        desc.os = OsKind::Windows;
        desc.abi = desc.address_width == AddressWidth::Bits64
                       ? AbiKind::PeWindows64
                       : AbiKind::PeWindows32;
    } else if (lower == "none" || lower.find("bare") != std::string::npos ||
               lower == "standalone") {
        desc.os = OsKind::BareMetal;
        desc.abi = AbiKind::Standalone;
    } else if (lower.find("freebsd") != std::string::npos) {
        desc.os = OsKind::FreeBsd;
        desc.abi = AbiKind::FreeBsd;
    } else if (lower.find("openbsd") != std::string::npos) {
        desc.os = OsKind::OpenBsd;
        desc.abi = AbiKind::OpenBsd;
    } else if (lower.find("netbsd") != std::string::npos) {
        desc.os = OsKind::NetBsd;
        desc.abi = AbiKind::NetBsd;
    } else if (lower.find("svr4") != std::string::npos) {
        desc.abi = AbiKind::SysV;
    }
}

[[nodiscard]] RegisterCategory classify_rsp_register(
    std::string_view name,
    std::string_view type,
    std::string_view group,
    std::uint32_t bitsize) {
    const std::string lname = to_lower_ascii(name);
    const std::string ltype = to_lower_ascii(type);
    const std::string lgroup = to_lower_ascii(group);

    if (lname == "rip" || lname == "eip" || lname == "pc" || lname == "nip" || lname == "iar") {
        return RegisterCategory::InstructionPointer;
    }
    if (lname == "rsp" || lname == "esp" || lname == "sp" || lname == "x2" ||
        (lname == "r29" && ltype == "data_ptr")) {
        return RegisterCategory::StackPointer;
    }
    if (lname == "rbp" || lname == "ebp" || lname == "fp" || lname == "x29" || lname == "s0") {
        return RegisterCategory::FramePointer;
    }
    if (lname == "eflags" || lname == "rflags" || lname == "cpsr" || lname == "pstate" ||
        lname == "xpsr" || lname == "msr" || lname == "cr" || lname == "status") {
        return RegisterCategory::Flags;
    }
    if (lname == "fs_base" || lname == "gs_base" || lname == "tp" || lname == "tpidr" ||
        lname == "tpidr_el0" || lname == "cs" || lname == "ss" || lname == "ds" ||
        lname == "es" || lname == "fs" || lname == "gs") {
        return RegisterCategory::SegmentOrTls;
    }
    if (lgroup == "vector" || bitsize > 80u || ltype.starts_with("vec") ||
        lname.starts_with("xmm") || lname.starts_with("ymm") || lname.starts_with("zmm") ||
        lname.starts_with("vr")) {
        return RegisterCategory::Vector;
    }
    if (lgroup == "float" || lgroup == "fpu" || ltype.starts_with("ieee_") ||
        ltype.find("ext") != std::string::npos ||
        (lname.size() == 3u && lname.starts_with("st") && lname[2] >= '0' && lname[2] <= '7') ||
        (lname.size() >= 3u &&
         (lname.starts_with("ft") || lname.starts_with("fa") || lname.starts_with("fs")) &&
         lname[2] >= '0' && lname[2] <= '9')) {
        return RegisterCategory::FloatingPoint;
    }
    if (lgroup == "system" || lgroup == "csr" || lgroup == "cp0") {
        return RegisterCategory::System;
    }
    if (ltype == "code_ptr" && lname != "lr" && lname != "ra" &&
        lname != "x30" && lname != "r14" && lname != "ctr" &&
        lname != "r31" && lname != "$31" &&
        lname != "elr_el1" && lname != "elr_el2" && lname != "elr_el3" &&
        lname != "mepc" && lname != "sepc") {
        return RegisterCategory::InstructionPointer;
    }
    return RegisterCategory::General;
}

struct TargetXmlTraversalState {
    RspTargetDescription desc{};
    const AnnexFetcherFn& fetch_annex;
    std::size_t max_depth{8};
    std::size_t max_docs{64};
    std::size_t docs_loaded{0};
    std::uint32_t next_regnum{0};
    std::unordered_set<std::string> active_includes{};
};

[[nodiscard]] Result<void> walk_target_xml_element(
    const XmlElement& elem,
    std::string_view current_feature,
    std::size_t depth,
    TargetXmlTraversalState& state) {
    if (is_xi_include_tag(elem.name)) {
        const auto href_opt = elem.attr("href");
        if (!href_opt.has_value()) {
            return make_error("Missing href attribute on <xi:include> in target.xml");
        }
        const std::string href(*href_opt);
        if (auto ok = validate_annex_href(href); !ok) {
            return ok;
        }
        if (depth >= state.max_depth) {
            return make_error("Exceeded maximum <xi:include> nesting depth in target.xml");
        }
        if (state.docs_loaded >= state.max_docs) {
            return make_error("Exceeded maximum <xi:include> annex count in target.xml");
        }
        if (state.active_includes.contains(href)) {
            return make_error("Detected <xi:include> cycle involving '" + href + "'");
        }
        if (!state.fetch_annex) {
            return make_error("Cannot resolve <xi:include href='" + href + "'> without annex fetcher");
        }

        auto annex_xml = state.fetch_annex(href);
        if (!annex_xml) {
            return std::unexpected(annex_xml.error());
        }
        ++state.docs_loaded;
        state.active_includes.insert(href);

        BoundedXmlParser parser(*annex_xml);
        auto annex_root = parser.parse_document();
        if (!annex_root) {
            state.active_includes.erase(href);
            return std::unexpected(annex_root.error());
        }
        auto res = walk_target_xml_element(*annex_root, current_feature, depth + 1u, state);
        state.active_includes.erase(href);
        return res;
    }

    if (elem.name == "target") {
        if (const auto endian_attr = elem.attr("endian"); endian_attr.has_value()) {
            if (iequals_ascii(*endian_attr, "big")) {
                state.desc.endianness = Endianness::Big;
                state.desc.explicit_endianness = true;
            } else if (iequals_ascii(*endian_attr, "little")) {
                state.desc.endianness = Endianness::Little;
                state.desc.explicit_endianness = true;
            }
        }
        for (const auto& child : elem.children) {
            if (auto r = walk_target_xml_element(child, current_feature, depth, state); !r) {
                return r;
            }
        }
        return {};
    }

    if (elem.name == "architecture") {
        state.desc.raw_architecture = elem.text;
        apply_architecture_string(elem.text, state.desc);
        return {};
    }

    if (elem.name == "osabi") {
        state.desc.raw_osabi = elem.text;
        apply_osabi_string(elem.text, state.desc);
        return {};
    }

    if (elem.name == "endian") {
        if (iequals_ascii(elem.text, "big")) {
            state.desc.endianness = Endianness::Big;
            state.desc.explicit_endianness = true;
        } else if (iequals_ascii(elem.text, "little")) {
            state.desc.endianness = Endianness::Little;
            state.desc.explicit_endianness = true;
        }
        return {};
    }

    if (elem.name == "feature") {
        const std::string feat_name(elem.attr("name").value_or(current_feature));
        if (!feat_name.empty()) {
            state.desc.feature_names.push_back(feat_name);
        }
        for (const auto& child : elem.children) {
            if (auto r = walk_target_xml_element(child, feat_name, depth, state); !r) {
                return r;
            }
        }
        return {};
    }

    if (elem.name == "flags") {
        RspFlagsTypeSpec ftype{};
        ftype.id = std::string(elem.attr("id").value_or(""));
        if (const auto sz_str = elem.attr("size"); sz_str.has_value()) {
            if (const auto sz = parse_uint64_auto(*sz_str); sz.has_value() && *sz <= 16u) {
                ftype.byte_size = static_cast<std::uint32_t>(*sz);
            }
        }
        for (const auto& child : elem.children) {
            if (child.name != "field") {
                continue;
            }
            const auto fname = child.attr("name");
            const auto fstart = child.attr("start");
            const auto fend = child.attr("end");
            if (!fname.has_value() || !fstart.has_value()) {
                continue;
            }
            const auto start_v = parse_uint64_auto(*fstart);
            const auto end_v = fend.has_value() ? parse_uint64_auto(*fend) : start_v;
            if (start_v.has_value() && end_v.has_value() && *start_v < 64u && *end_v < 64u) {
                ftype.fields.push_back(RspFlagFieldSpec{
                    .name = std::string(*fname),
                    .start_bit = static_cast<std::uint8_t>(*start_v),
                    .end_bit = static_cast<std::uint8_t>(*end_v),
                });
            }
        }
        if (!ftype.id.empty()) {
            state.desc.flags_types.push_back(std::move(ftype));
        }
        return {};
    }

    if (elem.name == "reg") {
        const auto name_opt = elem.attr("name");
        const auto bitsize_opt = elem.attr("bitsize");
        if (!name_opt.has_value() || name_opt->empty() || !bitsize_opt.has_value()) {
            return make_error("Malformed <reg> element missing name or bitsize in target.xml");
        }
        const auto bitsize_v = parse_uint64_auto(*bitsize_opt);
        if (!bitsize_v.has_value() || *bitsize_v == 0u || *bitsize_v > 8192u) {
            return make_error("Invalid bitsize on <reg name='" + std::string(*name_opt) + "'>");
        }

        std::uint32_t regnum = state.next_regnum;
        if (const auto regnum_opt = elem.attr("regnum"); regnum_opt.has_value()) {
            const auto parsed_regnum = parse_uint64_auto(*regnum_opt);
            if (!parsed_regnum.has_value() || *parsed_regnum > 0xFFFF'FFFEu) {
                return make_error("Invalid regnum on <reg name='" + std::string(*name_opt) + "'>");
            }
            regnum = static_cast<std::uint32_t>(*parsed_regnum);
        }
        state.next_regnum = regnum + 1u;

        RspRegisterSpec spec{};
        spec.name = std::string(*name_opt);
        spec.regnum = regnum;
        spec.bitsize = static_cast<std::uint32_t>(*bitsize_v);
        spec.type = std::string(elem.attr("type").value_or("int"));
        spec.group = std::string(elem.attr("group").value_or(""));
        spec.feature_name = std::string(current_feature);
        if (const auto sr = elem.attr("save-restore"); sr.has_value() && iequals_ascii(*sr, "no")) {
            spec.save_restore = false;
        }
        spec.category = classify_rsp_register(spec.name, spec.type, spec.group, spec.bitsize);
        state.desc.registers.push_back(std::move(spec));
        return {};
    }

    // Other valid GDB target.xml elements (<vector>, <union>, <struct>, <enum>) may wrap subnodes;
    // still honor nested <xi:include> if any.
    for (const auto& child : elem.children) {
        if (is_xi_include_tag(child.name)) {
            if (auto r = walk_target_xml_element(child, current_feature, depth, state); !r) {
                return r;
            }
        }
    }
    return {};
}

void infer_architecture_from_features_if_unknown(RspTargetDescription& desc) {
    if (desc.architecture != Architecture::Unknown) {
        return;
    }
    std::uint32_t pointer_bits = 0;
    for (const auto& reg : desc.registers) {
        if (reg.category == RegisterCategory::InstructionPointer ||
            reg.category == RegisterCategory::StackPointer) {
            pointer_bits = std::max(pointer_bits, reg.bitsize);
        }
    }

    for (const auto& feat : desc.feature_names) {
        const std::string lfeat = to_lower_ascii(feat);
        if (lfeat.find("org.gnu.gdb.i386") != std::string::npos) {
            const bool is64 = lfeat.find("64bit") != std::string::npos || pointer_bits == 64u;
            desc.architecture = is64 ? Architecture::X86_64 : Architecture::X86;
            desc.address_width = is64 ? AddressWidth::Bits64 : AddressWidth::Bits32;
            break;
        }
        if (lfeat.find("org.gnu.gdb.aarch64") != std::string::npos) {
            desc.architecture = Architecture::ARM64;
            desc.address_width = AddressWidth::Bits64;
            break;
        }
        if (lfeat.find("org.gnu.gdb.arm") != std::string::npos) {
            desc.architecture = Architecture::ARM;
            desc.address_width = AddressWidth::Bits32;
            break;
        }
        if (lfeat.find("org.gnu.gdb.riscv") != std::string::npos) {
            const bool is64 = pointer_bits == 64u;
            desc.architecture = is64 ? Architecture::RISCV64 : Architecture::RISCV32;
            desc.address_width = is64 ? AddressWidth::Bits64 : AddressWidth::Bits32;
            break;
        }
        if (lfeat.find("org.gnu.gdb.power") != std::string::npos) {
            const bool is64 = lfeat.find("64") != std::string::npos || pointer_bits == 64u;
            desc.architecture = is64 ? Architecture::PowerPC64 : Architecture::PowerPC;
            desc.address_width = is64 ? AddressWidth::Bits64 : AddressWidth::Bits32;
            if (!desc.explicit_endianness) {
                desc.endianness = Endianness::Big;
            }
            break;
        }
        if (lfeat.find("org.gnu.gdb.mips") != std::string::npos) {
            const bool is64 = pointer_bits == 64u;
            desc.architecture = is64 ? Architecture::MIPS64 : Architecture::MIPS32;
            desc.address_width = is64 ? AddressWidth::Bits64 : AddressWidth::Bits32;
            if (!desc.explicit_endianness) {
                desc.endianness = Endianness::Big;
            }
            break;
        }
    }
}

}  // namespace

Result<RspTargetDescription> parse_rsp_target_xml(
    std::string_view root_xml,
    const AnnexFetcherFn& fetch_annex,
    std::size_t max_include_depth,
    std::size_t max_include_documents) {
    BoundedXmlParser parser(root_xml);
    auto root = parser.parse_document();
    if (!root) {
        return std::unexpected(root.error());
    }
    if (root->name != "target" && root->name != "feature") {
        return make_error("Expected <target> root element in GDB RSP target.xml");
    }

    TargetXmlTraversalState state{
        .desc = RspTargetDescription{},
        .fetch_annex = fetch_annex,
        .max_depth = max_include_depth,
        .max_docs = max_include_documents,
        .docs_loaded = 0u,
        .next_regnum = 0u,
        .active_includes = {},
    };

    if (auto res = walk_target_xml_element(*root, "", 0u, state); !res) {
        return std::unexpected(res.error());
    }
    infer_architecture_from_features_if_unknown(state.desc);
    return std::move(state.desc);
}

Result<RspRegisterValue> decode_rsp_register_hex(
    const RspRegisterSpec& spec,
    std::string_view hex_or_xx,
    Endianness endianness) {
    const std::size_t byte_len = static_cast<std::size_t>((spec.bitsize + 7u) / 8u);
    const std::size_t expected_chars = byte_len * 2u;
    if (hex_or_xx.size() < expected_chars) {
        return make_error(
            "Truncated hex buffer for register '" + spec.name + "' (expected " +
            std::to_string(expected_chars) + " chars)");
    }

    RspRegisterValue out{};
    out.name = spec.name;
    out.regnum = spec.regnum;
    out.bit_width = static_cast<std::uint16_t>(std::min<std::uint32_t>(spec.bitsize, 0xFFFFu));
    out.category = spec.category;
    out.raw_bytes.assign(byte_len, 0u);
    out.valid_bytes.assign(byte_len, 0u);

    std::size_t valid_count = 0;
    for (std::size_t b = 0; b < byte_len; ++b) {
        const char c0 = hex_or_xx[b * 2u];
        const char c1 = hex_or_xx[b * 2u + 1u];
        if ((c0 == 'x' || c0 == 'X') && (c1 == 'x' || c1 == 'X')) {
            out.raw_bytes[b] = 0u;
            out.valid_bytes[b] = 0u;
            continue;
        }
        const auto hi = hex_nibble(c0);
        const auto lo = hex_nibble(c1);
        if (!hi.has_value() || !lo.has_value()) {
            return make_error("Invalid hex/'xx' byte pair in GDB RSP register '" + spec.name + "'");
        }
        out.raw_bytes[b] = static_cast<std::uint8_t>((*hi << 4u) | *lo);
        out.valid_bytes[b] = 1u;
        ++valid_count;
    }

    if (valid_count == 0u) {
        out.availability = Availability::Unavailable;
        out.value_u64 = std::nullopt;
        out.formatted = "unavailable";
        return out;
    }

    if (valid_count < byte_len) {
        out.availability = Availability::Partial;
        out.value_u64 = std::nullopt;
        std::string fmt = "0x";
        fmt.reserve(2u + byte_len * 2u);
        for (std::size_t idx = 0; idx < byte_len; ++idx) {
            const std::size_t b =
                (endianness == Endianness::Little) ? (byte_len - 1u - idx) : idx;
            if (out.valid_bytes[b] == 0u) {
                fmt.append("xx");
            } else {
                fmt.append(format_hex_u64(out.raw_bytes[b], 2u));
            }
        }
        out.formatted = std::move(fmt);
        return out;
    }

    out.availability = Availability::Available;
    if (byte_len <= 8u) {
        std::uint64_t val = 0;
        if (endianness == Endianness::Little) {
            for (std::size_t b = 0; b < byte_len; ++b) {
                val |= static_cast<std::uint64_t>(out.raw_bytes[b]) << (b * 8u);
            }
        } else {
            for (std::size_t b = 0; b < byte_len; ++b) {
                val = (val << 8u) | static_cast<std::uint64_t>(out.raw_bytes[b]);
            }
        }
        if (spec.bitsize < 64u) {
            const std::uint64_t mask = (std::uint64_t{1} << spec.bitsize) - 1u;
            val &= mask;
        }
        out.value_u64 = val;
        out.formatted = "0x" + format_hex_u64(val, byte_len * 2u);
    } else {
        out.value_u64 = std::nullopt;
        std::string fmt = "0x";
        fmt.reserve(2u + byte_len * 2u);
        for (std::size_t idx = 0; idx < byte_len; ++idx) {
            const std::size_t b =
                (endianness == Endianness::Little) ? (byte_len - 1u - idx) : idx;
            fmt.append(format_hex_u64(out.raw_bytes[b], 2u));
        }
        out.formatted = std::move(fmt);
    }
    return out;
}

Result<std::vector<RspRegisterValue>> decode_rsp_g_packet(
    const RspTargetDescription& description,
    std::string_view g_hex_payload) {
    g_hex_payload = trim_ascii(g_hex_payload);
    if (is_rsp_error_reply(g_hex_payload)) {
        return make_error("GDB RSP 'g' register read failed with stub error '" +
                          std::string(g_hex_payload) + "'");
    }
    if ((g_hex_payload.size() % 2u) != 0u) {
        return make_error("Odd-length hex payload in GDB RSP 'g' register packet");
    }

    std::vector<std::size_t> order(description.registers.size());
    for (std::size_t i = 0; i < order.size(); ++i) {
        order[i] = i;
    }
    std::stable_sort(order.begin(), order.end(), [&](std::size_t a, std::size_t b) noexcept {
        return description.registers[a].regnum < description.registers[b].regnum;
    });

    std::vector<RspRegisterValue> results;
    results.reserve(description.registers.size());

    std::size_t cursor = 0;
    for (const std::size_t idx : order) {
        const RspRegisterSpec& spec = description.registers[idx];
        const std::size_t byte_len = static_cast<std::size_t>((spec.bitsize + 7u) / 8u);
        const std::size_t char_len = byte_len * 2u;

        if (cursor + char_len <= g_hex_payload.size()) {
            auto decoded = decode_rsp_register_hex(
                spec, g_hex_payload.substr(cursor, char_len), description.endianness);
            if (!decoded) {
                return std::unexpected(decoded.error());
            }
            results.push_back(std::move(*decoded));
            cursor += char_len;
        } else {
            RspRegisterValue missing{};
            missing.name = spec.name;
            missing.regnum = spec.regnum;
            missing.bit_width =
                static_cast<std::uint16_t>(std::min<std::uint32_t>(spec.bitsize, 0xFFFFu));
            missing.category = spec.category;
            missing.availability = Availability::Unavailable;
            missing.raw_bytes.assign(byte_len, 0u);
            missing.valid_bytes.assign(byte_len, 0u);
            missing.formatted = "unavailable";
            results.push_back(std::move(missing));
            cursor = g_hex_payload.size();
        }
    }

    return results;
}

Result<std::vector<RspMemoryMapEntry>> parse_rsp_memory_map_xml(std::string_view xml) {
    BoundedXmlParser parser(xml);
    auto root = parser.parse_document();
    if (!root) {
        return std::unexpected(root.error());
    }
    if (root->name != "memory-map") {
        return make_error("Expected <memory-map> root element in GDB RSP memory-map XML");
    }

    std::vector<RspMemoryMapEntry> entries;
    entries.reserve(root->children.size());

    for (const auto& child : root->children) {
        if (child.name != "memory") {
            continue;
        }
        const auto start_attr = child.attr("start");
        const auto len_attr = child.attr("length");
        if (!start_attr.has_value() || !len_attr.has_value()) {
            return make_error("Missing start or length attribute on <memory> in memory-map XML");
        }
        const auto start = parse_uint64_auto(*start_attr);
        const auto length = parse_uint64_auto(*len_attr);
        if (!start.has_value() || !length.has_value()) {
            return make_error("Invalid numeric start/length in memory-map XML");
        }
        if (!checked_add_u64(*start, *length).has_value()) {
            return make_error("Overflowing address range in GDB RSP memory-map XML");
        }

        RspMemoryMapEntry entry{};
        entry.start = *start;
        entry.length = *length;

        const std::string_view type_str = child.attr("type").value_or("ram");
        if (iequals_ascii(type_str, "ram")) {
            entry.type = RspMemoryRegionType::Ram;
        } else if (iequals_ascii(type_str, "rom")) {
            entry.type = RspMemoryRegionType::Rom;
        } else if (iequals_ascii(type_str, "flash")) {
            entry.type = RspMemoryRegionType::Flash;
        } else {
            entry.type = RspMemoryRegionType::Unknown;
        }

        for (const auto& prop : child.children) {
            if (prop.name != "property") {
                continue;
            }
            const std::string_view pname = prop.attr("name").value_or("");
            if (pname == "blocksize") {
                entry.blocksize = parse_uint64_auto(prop.text);
            } else if (pname == "permissions" || pname == "access") {
                entry.permissions = prop.text;
            } else if (pname == "name") {
                entry.name = prop.text;
            }
        }
        entries.push_back(std::move(entry));
    }
    return entries;
}

Result<std::vector<RspLibraryEntry>> parse_rsp_libraries_xml(std::string_view xml) {
    BoundedXmlParser parser(xml);
    auto root = parser.parse_document();
    if (!root) {
        return std::unexpected(root.error());
    }
    if (root->name != "library-list-svr4" && root->name != "library-list") {
        return make_error("Expected <library-list-svr4> or <library-list> root in libraries XML");
    }

    std::optional<std::uint64_t> main_lm{};
    if (const auto main_lm_attr = root->attr("main-lm"); main_lm_attr.has_value()) {
        main_lm = parse_uint64_auto(*main_lm_attr);
    }

    std::vector<RspLibraryEntry> libs;
    libs.reserve(root->children.size());

    for (const auto& child : root->children) {
        if (child.name != "library") {
            continue;
        }
        RspLibraryEntry lib{};
        lib.name = std::string(child.attr("name").value_or(""));
        if (const auto l_addr = child.attr("l_addr"); l_addr.has_value()) {
            lib.base_address = parse_uint64_auto(*l_addr).value_or(0u);
        }
        if (const auto l_ld = child.attr("l_ld"); l_ld.has_value()) {
            lib.dynamic_address = parse_uint64_auto(*l_ld).value_or(0u);
        }
        if (const auto lm = child.attr("lm"); lm.has_value()) {
            lib.link_map_address = parse_uint64_auto(*lm).value_or(0u);
            if (main_lm.has_value() && lib.link_map_address == *main_lm) {
                lib.is_main_module = true;
            }
        }
        for (const auto& seg : child.children) {
            if (seg.name == "segment" || seg.name == "section") {
                if (const auto addr_attr = seg.attr("address"); addr_attr.has_value()) {
                    if (const auto addr = parse_uint64_auto(*addr_attr); addr.has_value()) {
                        lib.segment_addresses.push_back(*addr);
                    }
                }
            }
        }
        if (lib.base_address == 0u && !lib.segment_addresses.empty()) {
            lib.base_address = lib.segment_addresses.front();
        }
        libs.push_back(std::move(lib));
    }
    return libs;
}

// ---------------------------------------------------------------------------
// Thread ID parsing & collision-free 64-bit / multiprocess mapper
// ---------------------------------------------------------------------------

namespace {

[[nodiscard]] Result<std::pair<RspIdKind, std::uint64_t>> parse_single_rsp_id_component(
    std::string_view part) {
    part = trim_ascii(part);
    if (part.empty()) {
        return make_error("Empty ID component in GDB RSP thread identifier");
    }
    if (part == "-1") {
        return std::pair{RspIdKind::All, std::uint64_t{0}};
    }
    if (part.front() == '-') {
        return make_error("Invalid negative GDB RSP identifier '" + std::string(part) + "'");
    }
    const auto val = parse_uint64_hex(part);
    if (!val.has_value()) {
        return make_error("Invalid hex GDB RSP identifier '" + std::string(part) + "'");
    }
    if (*val == 0u) {
        return std::pair{RspIdKind::Any, std::uint64_t{0}};
    }
    return std::pair{RspIdKind::Explicit, *val};
}

}  // namespace

Result<RspRemoteThreadId> parse_rsp_thread_id(std::string_view token) {
    token = trim_ascii(token);
    if (token.empty()) {
        return make_error("Empty GDB RSP thread identifier");
    }

    RspRemoteThreadId out{};
    out.wire_token = std::string(token);

    if (token.front() == 'p') {
        out.multiprocess = true;
        const std::string_view rest = token.substr(1u);
        const std::size_t dot = rest.find('.');
        if (dot == std::string_view::npos) {
            auto pid_comp = parse_single_rsp_id_component(rest);
            if (!pid_comp) {
                return std::unexpected(pid_comp.error());
            }
            out.pid_kind = pid_comp->first;
            out.pid = pid_comp->second;
            out.tid_kind = RspIdKind::All;
            out.tid = 0u;
            return out;
        }
        auto pid_comp = parse_single_rsp_id_component(rest.substr(0, dot));
        if (!pid_comp) {
            return std::unexpected(pid_comp.error());
        }
        auto tid_comp = parse_single_rsp_id_component(rest.substr(dot + 1u));
        if (!tid_comp) {
            return std::unexpected(tid_comp.error());
        }
        out.pid_kind = pid_comp->first;
        out.pid = pid_comp->second;
        out.tid_kind = tid_comp->first;
        out.tid = tid_comp->second;
        return out;
    }

    auto tid_comp = parse_single_rsp_id_component(token);
    if (!tid_comp) {
        return std::unexpected(tid_comp.error());
    }
    out.multiprocess = false;
    out.pid_kind = RspIdKind::Any;
    out.pid = 0u;
    out.tid_kind = tid_comp->first;
    out.tid = tid_comp->second;
    return out;
}

Result<std::vector<RspRemoteThreadId>> parse_rsp_thread_info_packet(
    std::string_view reply,
    bool& reached_end) {
    reply = trim_ascii(reply);
    reached_end = false;
    if (reply.empty() || reply == "l") {
        reached_end = true;
        return std::vector<RspRemoteThreadId>{};
    }
    if (reply.front() != 'm') {
        if (is_rsp_error_reply(reply)) {
            return make_error("GDB RSP thread enumeration failed with '" + std::string(reply) + "'");
        }
        return make_error("Unexpected GDB RSP qfThreadInfo/qsThreadInfo reply");
    }

    std::vector<RspRemoteThreadId> out;
    const std::string_view list = reply.substr(1u);
    std::size_t pos = 0;
    while (pos <= list.size()) {
        const std::size_t comma = list.find(',', pos);
        const std::string_view tok = trim_ascii(
            comma == std::string_view::npos ? list.substr(pos) : list.substr(pos, comma - pos));
        if (!tok.empty()) {
            auto parsed = parse_rsp_thread_id(tok);
            if (!parsed) {
                return std::unexpected(parsed.error());
            }
            out.push_back(std::move(*parsed));
        }
        if (comma == std::string_view::npos) {
            break;
        }
        pos = comma + 1u;
    }
    return out;
}

ThreadId RspThreadIdMapper::intern(const RspRemoteThreadId& remote_id) {
    if (const auto it = wire_to_local_.find(remote_id.wire_token); it != wire_to_local_.end()) {
        return it->second;
    }

    if (primary_pid_ == 0u && remote_id.multiprocess && remote_id.pid_kind == RspIdKind::Explicit) {
        primary_pid_ = remote_id.pid;
    }

    ThreadId chosen = 0u;
    const bool matches_primary_process =
        !remote_id.multiprocess || primary_pid_ == 0u ||
        (remote_id.pid_kind == RspIdKind::Explicit && remote_id.pid == primary_pid_);

    if (matches_primary_process &&
        remote_id.tid_kind == RspIdKind::Explicit &&
        remote_id.tid > 0u &&
        remote_id.tid <= 0x7FFF'FFFFu) {
        const auto direct = static_cast<ThreadId>(remote_id.tid);
        if (!local_to_remote_.contains(direct)) {
            chosen = direct;
        }
    }

    if (chosen == 0u) {
        while (chosen == 0u || local_to_remote_.contains(chosen)) {
            chosen = next_synthetic_tid_++;
            if (next_synthetic_tid_ == 0u) {
                next_synthetic_tid_ = 1u;
            }
        }
    }

    wire_to_local_.emplace(remote_id.wire_token, chosen);
    local_to_remote_.emplace(chosen, remote_id);
    return chosen;
}

std::optional<RspRemoteThreadId> RspThreadIdMapper::lookup_remote(ThreadId local_tid) const {
    const auto it = local_to_remote_.find(local_tid);
    if (it == local_to_remote_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<ThreadId> RspThreadIdMapper::lookup_local(std::string_view wire_token) const {
    const auto it = wire_to_local_.find(std::string(wire_token));
    if (it == wire_to_local_.end()) {
        return std::nullopt;
    }
    return it->second;
}

// ---------------------------------------------------------------------------
// RspClient implementation
// ---------------------------------------------------------------------------

RspClient::RspClient(std::unique_ptr<IRspTransport> transport, RspClientOptions options)
    : transport_(std::move(transport)), options_(options) {
    rx_buffer_.reserve(4096u);
}

Result<std::uint8_t> RspClient::read_byte(
    std::chrono::milliseconds timeout,
    std::stop_token stop_token) {
    if (rx_offset_ < rx_buffer_.size()) {
        const std::uint8_t b = rx_buffer_[rx_offset_++];
        if (rx_offset_ == rx_buffer_.size()) {
            rx_buffer_.clear();
            rx_offset_ = 0u;
        }
        return b;
    }

    if (transport_ == nullptr || !transport_->is_open()) {
        return make_error("GDB RSP transport is not open");
    }

    std::array<std::uint8_t, 4096> chunk{};
    auto res = transport_->read_some(chunk, timeout, stop_token);
    if (!res) {
        return std::unexpected(res.error());
    }
    switch (res->status) {
        case RspIoStatus::Ok:
            break;
        case RspIoStatus::Timeout:
            return make_error("Timed out waiting for GDB RSP reply byte");
        case RspIoStatus::EndOfStream:
            return make_error("GDB RSP stub closed the connection");
        case RspIoStatus::Cancelled:
            return make_error("GDB RSP read cancelled");
    }
    if (res->bytes_read == 0u) {
        return make_error("GDB RSP transport returned zero bytes without EOF/Timeout");
    }

    rx_buffer_.assign(chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(res->bytes_read));
    rx_offset_ = 1u;
    const std::uint8_t first = rx_buffer_[0];
    if (rx_offset_ == rx_buffer_.size()) {
        rx_buffer_.clear();
        rx_offset_ = 0u;
    }
    return first;
}

Result<std::string> RspClient::receive_packet_with_nak_retries(std::stop_token stop_token) {
    const std::size_t max_attempts = (no_ack_mode_ ? 0u : options_.max_retries) + 1u;
    const std::size_t max_wire_bytes =
        std::max(options_.max_packet_size, options_.max_annex_size) * 2u + 64u;

    for (std::size_t attempt = 0; attempt < max_attempts; ++attempt) {
        std::size_t skipped_preamble = 0;
        for (;;) {
            auto b = read_byte(options_.command_timeout, stop_token);
            if (!b) {
                return std::unexpected(b.error());
            }
            if (*b == static_cast<std::uint8_t>('$')) {
                break;
            }
            ++skipped_preamble;
            if (skipped_preamble > 4096u) {
                return make_error("Exceeded maximum preamble scan waiting for '$' in GDB RSP stream");
            }
        }

        std::string wire_body;
        for (;;) {
            auto b = read_byte(options_.command_timeout, stop_token);
            if (!b) {
                return std::unexpected(b.error());
            }
            if (*b == static_cast<std::uint8_t>('#')) {
                break;
            }
            if (*b == static_cast<std::uint8_t>('$')) {
                // Unescaped '$' restarts frame synchronization per GDB RSP spec.
                wire_body.clear();
                continue;
            }
            if (wire_body.size() >= max_wire_bytes) {
                return make_error("GDB RSP frame body exceeds maximum wire size bound");
            }
            wire_body.push_back(static_cast<char>(*b));
        }

        const auto c0 = read_byte(options_.command_timeout, stop_token);
        if (!c0) {
            return std::unexpected(c0.error());
        }
        const auto c1 = read_byte(options_.command_timeout, stop_token);
        if (!c1) {
            return std::unexpected(c1.error());
        }

        const auto hi = hex_nibble(static_cast<char>(*c0));
        const auto lo = hex_nibble(static_cast<char>(*c1));
        const std::uint8_t actual_csum = compute_rsp_checksum(wire_body);
        const bool valid_csum =
            hi.has_value() && lo.has_value() &&
            static_cast<std::uint8_t>((*hi << 4u) | *lo) == actual_csum;

        if (!valid_csum) {
            if (no_ack_mode_) {
                return make_error("Corrupt GDB RSP packet checksum in QStartNoAckMode");
            }
            if (attempt + 1u >= max_attempts) {
                return make_error("GDB RSP reply checksum failed after bounded NAK retries");
            }
            const std::array<std::uint8_t, 1> nak{static_cast<std::uint8_t>('-')};
            if (auto w = transport_->write_all(nak, options_.command_timeout, stop_token); !w) {
                return std::unexpected(w.error());
            }
            continue;
        }

        if (!no_ack_mode_) {
            const std::array<std::uint8_t, 1> ack{static_cast<std::uint8_t>('+')};
            if (auto w = transport_->write_all(ack, options_.command_timeout, stop_token); !w) {
                return std::unexpected(w.error());
            }
        }
        return rsp_decode_wire_payload(wire_body, options_.max_annex_size);
    }

    return make_error("GDB RSP failed to receive valid packet");
}

Result<std::string> RspClient::send_command(
    std::string_view payload,
    std::stop_token stop_token) {
    if (options_.strict_read_only && is_mutating_rsp_packet(payload)) {
        return make_error(
            "Refusing to transmit mutating GDB RSP command in strictly read-only session");
    }
    if (transport_ == nullptr || !transport_->is_open()) {
        return make_error("GDB RSP transport is not connected");
    }

    const std::string frame = rsp_encode_frame(payload);
    const std::span<const std::uint8_t> frame_bytes(
        reinterpret_cast<const std::uint8_t*>(frame.data()), frame.size());

    if (no_ack_mode_) {
        if (auto w = transport_->write_all(frame_bytes, options_.command_timeout, stop_token); !w) {
            return std::unexpected(w.error());
        }
        return receive_packet_with_nak_retries(stop_token);
    }

    const std::size_t max_tx_attempts = options_.max_retries + 1u;
    bool got_ack = false;
    for (std::size_t attempt = 0; attempt < max_tx_attempts; ++attempt) {
        if (auto w = transport_->write_all(frame_bytes, options_.command_timeout, stop_token); !w) {
            return std::unexpected(w.error());
        }

        bool retransmit = false;
        std::size_t noise = 0;
        while (!got_ack && !retransmit) {
            auto b = read_byte(options_.command_timeout, stop_token);
            if (!b) {
                return std::unexpected(b.error());
            }
            if (*b == static_cast<std::uint8_t>('+')) {
                got_ack = true;
            } else if (*b == static_cast<std::uint8_t>('-')) {
                retransmit = true;
            } else {
                ++noise;
                if (noise > 256u) {
                    return make_error("Expected '+' or '-' ACK/NAK from GDB RSP stub");
                }
            }
        }
        if (got_ack) {
            break;
        }
    }

    if (!got_ack) {
        return make_error("GDB RSP command rejected with repeated '-' NAKs from stub");
    }

    return receive_packet_with_nak_retries(stop_token);
}

Result<bool> RspClient::enable_no_ack_mode(std::stop_token stop_token) {
    if (no_ack_mode_) {
        return true;
    }
    auto reply = send_command("QStartNoAckMode", stop_token);
    if (!reply) {
        return std::unexpected(reply.error());
    }
    if (*reply == "OK") {
        no_ack_mode_ = true;
        capabilities_.no_ack_mode_active = true;
        return true;
    }
    return false;
}

Result<RspCapabilities> RspClient::negotiate(std::stop_token stop_token) {
    const std::string cmd =
        "qSupported:multiprocess+;QStartNoAckMode+;qXfer:features:read+;"
        "qXfer:memory-map:read+;qXfer:libraries-svr4:read+;qXfer:libraries:read+;"
        "qXfer:auxv:read+";
    auto reply = send_command(cmd, stop_token);
    if (!reply) {
        return std::unexpected(reply.error());
    }

    capabilities_ = parse_qsupported_reply(*reply, options_.max_packet_size);
    if (options_.request_no_ack_mode && capabilities_.no_ack_mode_supported) {
        auto ack_res = enable_no_ack_mode(stop_token);
        if (!ack_res) {
            return std::unexpected(ack_res.error());
        }
    }
    return capabilities_;
}

Result<std::optional<std::string>> RspClient::read_qxfer(
    std::string_view object,
    std::string_view annex,
    std::stop_token stop_token) {
    const std::size_t effective_max_packet =
        std::clamp<std::size_t>(options_.max_packet_size, 64u, 16384u);
    const std::size_t desired_chunk =
        capabilities_.packet_size > 32u ? (capabilities_.packet_size - 16u) : 512u;
    const std::size_t chunk_req =
        std::clamp<std::size_t>(desired_chunk, 64u, effective_max_packet);

    std::string accumulated;
    std::uint64_t offset = 0;
    std::size_t empty_m_chunks = 0;

    for (;;) {
        const std::string cmd =
            "qXfer:" + std::string(object) + ":read:" + std::string(annex) + ":" +
            format_hex_u64(offset) + "," + format_hex_u64(chunk_req);

        auto reply = send_command(cmd, stop_token);
        if (!reply) {
            return std::unexpected(reply.error());
        }
        if (reply->empty()) {
            if (offset == 0u) {
                return std::optional<std::string>{std::nullopt};
            }
            return accumulated;
        }
        if (is_rsp_error_reply(*reply) || reply->front() == 'E') {
            return make_error(
                "GDB RSP qXfer:" + std::string(object) + ":read:" + std::string(annex) +
                " failed with '" + *reply + "'");
        }

        const char marker = reply->front();
        if (marker != 'm' && marker != 'l') {
            return make_error("Unexpected qXfer chunk prefix in GDB RSP reply");
        }

        const std::string_view chunk(reply->data() + 1u, reply->size() - 1u);
        if (chunk.size() > options_.max_annex_size - accumulated.size()) {
            return make_error("GDB RSP qXfer annex exceeds maximum configured size bound");
        }
        accumulated.append(chunk);
        offset += static_cast<std::uint64_t>(chunk.size());

        if (marker == 'l') {
            return accumulated;
        }
        if (chunk.empty()) {
            ++empty_m_chunks;
            if (empty_m_chunks > 4u) {
                return make_error("GDB RSP stub returned stalled empty 'm' chunks in qXfer");
            }
        } else {
            empty_m_chunks = 0u;
        }
    }
}

Result<std::optional<RspTargetDescription>> RspClient::read_target_description(
    std::stop_token stop_token) {
    auto root_xml = read_qxfer("features", "target.xml", stop_token);
    if (!root_xml) {
        return std::unexpected(root_xml.error());
    }
    if (!root_xml->has_value()) {
        return std::optional<RspTargetDescription>{std::nullopt};
    }

    const AnnexFetcherFn fetcher = [this, &stop_token](std::string_view href) -> Result<std::string> {
        auto annex = read_qxfer("features", href, stop_token);
        if (!annex) {
            return std::unexpected(annex.error());
        }
        if (!annex->has_value()) {
            return make_error("GDB RSP stub did not provide <xi:include> annex '" +
                              std::string(href) + "'");
        }
        return std::move(**annex);
    };

    auto parsed = parse_rsp_target_xml(
        **root_xml, fetcher, options_.max_xi_include_depth, options_.max_xi_include_documents);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    return std::optional<RspTargetDescription>{std::move(*parsed)};
}

Result<std::optional<std::vector<RspMemoryMapEntry>>> RspClient::read_memory_map(
    std::stop_token stop_token) {
    auto xml = read_qxfer("memory-map", "", stop_token);
    if (!xml) {
        return std::unexpected(xml.error());
    }
    if (!xml->has_value() || trim_ascii(**xml).empty()) {
        return std::optional<std::vector<RspMemoryMapEntry>>{std::nullopt};
    }
    auto parsed = parse_rsp_memory_map_xml(**xml);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    return std::optional<std::vector<RspMemoryMapEntry>>{std::move(*parsed)};
}

Result<std::optional<std::vector<RspLibraryEntry>>> RspClient::read_libraries(
    std::stop_token stop_token) {
    if (capabilities_.qxfer_libraries_svr4_read || !capabilities_.qxfer_libraries_read) {
        auto svr4 = read_qxfer("libraries-svr4", "", stop_token);
        if (svr4 && svr4->has_value() && !trim_ascii(**svr4).empty()) {
            auto parsed = parse_rsp_libraries_xml(**svr4);
            if (!parsed) {
                return std::unexpected(parsed.error());
            }
            return std::optional<std::vector<RspLibraryEntry>>{std::move(*parsed)};
        }
        if (!svr4 && capabilities_.qxfer_libraries_svr4_read) {
            return std::unexpected(svr4.error());
        }
    }

    auto generic = read_qxfer("libraries", "", stop_token);
    if (!generic) {
        return std::unexpected(generic.error());
    }
    if (!generic->has_value() || trim_ascii(**generic).empty()) {
        return std::optional<std::vector<RspLibraryEntry>>{std::nullopt};
    }
    auto parsed = parse_rsp_libraries_xml(**generic);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    return std::optional<std::vector<RspLibraryEntry>>{std::move(*parsed)};
}

Result<std::vector<RspRemoteThreadId>> RspClient::enumerate_threads(std::stop_token stop_token) {
    std::vector<RspRemoteThreadId> threads;
    auto first = send_command("qfThreadInfo", stop_token);
    if (!first) {
        return std::unexpected(first.error());
    }

    if (!first->empty()) {
        bool done = false;
        auto batch = parse_rsp_thread_info_packet(*first, done);
        if (!batch) {
            return std::unexpected(batch.error());
        }
        for (auto& t : *batch) {
            if (t.is_concrete_thread()) {
                threads.push_back(std::move(t));
            }
        }

        constexpr std::size_t kMaxThreadPages = 4096u;
        std::size_t pages = 0;
        while (!done) {
            ++pages;
            if (pages > kMaxThreadPages) {
                return make_error("Exceeded maximum qsThreadInfo pagination bound");
            }
            auto next = send_command("qsThreadInfo", stop_token);
            if (!next) {
                return std::unexpected(next.error());
            }
            auto next_batch = parse_rsp_thread_info_packet(*next, done);
            if (!next_batch) {
                return std::unexpected(next_batch.error());
            }
            for (auto& t : *next_batch) {
                if (t.is_concrete_thread()) {
                    threads.push_back(std::move(t));
                }
            }
        }
        if (!threads.empty()) {
            return threads;
        }
    }

    // Fallback to qC ("QC<thread-id>") for minimal bare-metal stubs that omit qfThreadInfo.
    auto qc = send_command("qC", stop_token);
    if (qc && qc->starts_with("QC") && qc->size() > 2u) {
        auto parsed = parse_rsp_thread_id(qc->substr(2u));
        if (parsed && parsed->is_concrete_thread()) {
            threads.push_back(std::move(*parsed));
        }
    }
    return threads;
}

Result<void> RspClient::select_general_thread(
    std::string_view wire_token,
    std::stop_token stop_token) {
    if (wire_token.empty() || wire_token == selected_hg_thread_) {
        return {};
    }
    auto reply = send_command("Hg" + std::string(wire_token), stop_token);
    if (!reply) {
        return std::unexpected(reply.error());
    }
    const std::string_view trimmed = trim_ascii(*reply);
    if (trimmed == "OK" || trimmed.empty()) {
        // Empty reply means the minimal single-thread stub ignores Hg; still usable.
        if (trimmed == "OK") {
            selected_hg_thread_ = std::string(wire_token);
        }
        return {};
    }
    if (is_rsp_error_reply(trimmed)) {
        return make_error("GDB RSP thread selection Hg" + std::string(wire_token) +
                          " failed with '" + std::string(trimmed) + "'");
    }
    return {};
}

Result<RspRegisterValue> RspClient::read_single_register(
    const RspRegisterSpec& spec,
    Endianness endianness,
    std::stop_token stop_token) {
    auto reply = send_command("p" + format_hex_u64(spec.regnum), stop_token);
    if (!reply) {
        return std::unexpected(reply.error());
    }
    const std::string_view trimmed_p = trim_ascii(*reply);
    if (trimmed_p.empty() || is_rsp_error_reply(trimmed_p)) {
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
        return unavail;
    }
    return decode_rsp_register_hex(spec, *reply, endianness);
}

Result<std::vector<RspRegisterValue>> RspClient::read_all_registers(
    const RspTargetDescription& description,
    std::stop_token stop_token) {
    auto g_reply = send_command("g", stop_token);
    if (!g_reply) {
        return std::unexpected(g_reply.error());
    }
    auto regs = decode_rsp_g_packet(description, *g_reply);
    if (!regs) {
        return regs;
    }

    // Probe trailing registers omitted from 'g' via 'p<hex_regnum>' if stub supports 'p'.
    const std::string_view trimmed_g = trim_ascii(*g_reply);
    bool p_supported = true;
    std::unordered_map<std::uint32_t, const RspRegisterSpec*> spec_by_num;
    spec_by_num.reserve(description.registers.size());
    for (const auto& s : description.registers) {
        spec_by_num.emplace(s.regnum, &s);
    }

    std::size_t g_cursor = 0;
    for (auto& reg : *regs) {
        const auto it = spec_by_num.find(reg.regnum);
        if (it == spec_by_num.end()) {
            continue;
        }
        const std::size_t char_len =
            static_cast<std::size_t>((it->second->bitsize + 7u) / 8u) * 2u;
        const bool covered_by_g = (g_cursor + char_len) <= trimmed_g.size();
        if (covered_by_g) {
            g_cursor += char_len;
            continue;
        }
        g_cursor = trimmed_g.size();

        if (!p_supported || !reg.is_unavailable()) {
            continue;
        }
        auto p_reply = send_command("p" + format_hex_u64(reg.regnum), stop_token);
        if (!p_reply) {
            p_supported = false;
            break;
        }
        const std::string_view trimmed_p = trim_ascii(*p_reply);
        if (trimmed_p.empty()) {
            p_supported = false;
            break;
        }
        if (is_rsp_error_reply(trimmed_p)) {
            continue;
        }
        if (auto single = decode_rsp_register_hex(*it->second, trimmed_p, description.endianness);
            single.has_value()) {
            reg = std::move(*single);
        }
    }

    return regs;
}

Result<std::size_t> RspClient::read_memory(
    std::uint64_t address,
    std::span<std::uint8_t> buffer,
    std::stop_token stop_token) {
    if (buffer.empty()) {
        return std::size_t{0};
    }

    const std::size_t effective_pkt =
        std::max<std::size_t>(64u, std::min(capabilities_.packet_size, options_.max_packet_size));
    const std::size_t max_chunk_bytes = std::max<std::size_t>(16u, (effective_pkt - 16u) / 2u);

    std::size_t total_read = 0;
    while (total_read < buffer.size()) {
        const auto chunk_addr = checked_add_u64(address, static_cast<std::uint64_t>(total_read));
        if (!chunk_addr.has_value()) {
            if (total_read > 0u) {
                return total_read;
            }
            return make_error("GDB RSP memory read address overflow");
        }

        const std::size_t req_len = std::min(buffer.size() - total_read, max_chunk_bytes);
        const std::string cmd =
            "m" + format_hex_u64(*chunk_addr) + "," + format_hex_u64(req_len);

        auto reply = send_command(cmd, stop_token);
        if (!reply) {
            if (total_read > 0u) {
                return total_read;
            }
            return std::unexpected(reply.error());
        }

        const std::string_view hex = trim_ascii(*reply);
        if (hex.empty() || is_rsp_error_reply(hex)) {
            if (total_read > 0u) {
                return total_read;
            }
            return make_error("GDB RSP memory read failed at 0x" + format_hex_u64(*chunk_addr) +
                              " (" + std::string(hex) + ")");
        }
        if ((hex.size() % 2u) != 0u) {
            return make_error("Odd-length hex reply to GDB RSP 'm' memory read");
        }

        const std::size_t got_bytes = std::min(req_len, hex.size() / 2u);
        if (got_bytes == 0u) {
            break;
        }
        for (std::size_t i = 0; i < got_bytes; ++i) {
            const auto hi = hex_nibble(hex[i * 2u]);
            const auto lo = hex_nibble(hex[i * 2u + 1u]);
            if (!hi.has_value() || !lo.has_value()) {
                if (total_read + i > 0u) {
                    return total_read + i;
                }
                return make_error("Non-hex byte in GDB RSP 'm' memory reply");
            }
            buffer[total_read + i] = static_cast<std::uint8_t>((*hi << 4u) | *lo);
        }
        total_read += got_bytes;
        if (got_bytes < req_len) {
            break;
        }
    }

    return total_read;
}

}  // namespace peelf
