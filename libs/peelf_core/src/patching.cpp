#include "peelf/patching.hpp"

#include "atomic_file_writer.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <format>
#include <fstream>
#include <limits>
#include <mutex>
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace peelf {

namespace detail {
namespace {

[[nodiscard]] std::uint64_t next_spill_sequence() noexcept {
    static std::atomic<std::uint64_t> counter{1};
    return counter.fetch_add(1, std::memory_order_relaxed);
}

[[nodiscard]] std::filesystem::path resolve_guarded_spill_temp_dir() {
#ifdef _WIN32
    wchar_t dir_buf[MAX_PATH] = {};
    const DWORD dir_len = ::GetTempPathW(MAX_PATH, dir_buf);
    if (dir_len == 0u || dir_len >= MAX_PATH) {
        return std::filesystem::current_path();
    }
    return std::filesystem::path(dir_buf);
#else
    std::error_code dir_ec;
    std::filesystem::path temp_dir = std::filesystem::temp_directory_path(dir_ec);
    if (dir_ec || temp_dir.empty()) {
        return std::filesystem::path("/tmp");
    }
    const std::string generic = temp_dir.generic_string();
    if (generic == "/mnt/c" || generic.starts_with("/mnt/c/")) {
        return std::filesystem::path("/tmp");
    }
    return temp_dir;
#endif
}

} // namespace

class PatchSpillWorkspace {
public:
    PatchSpillWorkspace(const PatchSpillWorkspace&) = delete;
    PatchSpillWorkspace& operator=(const PatchSpillWorkspace&) = delete;
    PatchSpillWorkspace(PatchSpillWorkspace&&) = delete;
    PatchSpillWorkspace& operator=(PatchSpillWorkspace&&) = delete;

    ~PatchSpillWorkspace() noexcept {
#ifdef _WIN32
        if (handle_ != INVALID_HANDLE_VALUE) {
            (void)::CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
#else
        if (fd_ >= 0) {
            (void)::close(fd_);
            fd_ = -1;
        }
#endif
    }

    [[nodiscard]] static Result<std::shared_ptr<PatchSpillWorkspace>> create() {
        const std::filesystem::path dir = resolve_guarded_spill_temp_dir();
#ifdef _WIN32
        const auto pid = static_cast<std::uint64_t>(::GetCurrentProcessId());
#else
        const auto pid = static_cast<std::uint64_t>(::getpid());
#endif
        for (unsigned int attempt = 0u; attempt < 64u; ++attempt) {
            const auto ticks = static_cast<std::uint64_t>(
                std::chrono::steady_clock::now().time_since_epoch().count());
            const std::uint64_t seq = next_spill_sequence();
            const std::filesystem::path candidate =
                dir / std::format(".peelf_patch_spill_{}_{}_{}.tmp", pid, ticks, seq);

#ifdef _WIN32
            HANDLE h = ::CreateFileW(
                candidate.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0u,
                nullptr,
                CREATE_NEW,
                FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                nullptr);
            if (h == INVALID_HANDLE_VALUE) {
                const DWORD err = ::GetLastError();
                if (err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS) {
                    continue;
                }
                return make_error(std::format(
                    "failed to create patch spillover workspace (Win32 error {})", err));
            }
            return std::shared_ptr<PatchSpillWorkspace>(new PatchSpillWorkspace(dir, h));
#else
            int flags = O_RDWR | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
            flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
            flags |= O_NOFOLLOW;
#endif
            const int fd = ::open(candidate.c_str(), flags, static_cast<mode_t>(0600));
            if (fd < 0) {
                if (errno == EEXIST) {
                    continue;
                }
                return make_error(std::format(
                    "failed to create patch spillover workspace: {}", std::strerror(errno)));
            }
            // Unlink immediately so the private 0600 inode leaves zero filesystem entries
            // and is reclaimed automatically by the kernel when fd_ closes.
            (void)::unlink(candidate.c_str());
            return std::shared_ptr<PatchSpillWorkspace>(new PatchSpillWorkspace(dir, fd));
#endif
        }
        return make_error("exhausted attempts creating exclusive patch spillover workspace");
    }

    [[nodiscard]] Result<std::uint64_t> append(std::span<const std::uint8_t> bytes) {
        std::scoped_lock lock(mutex_);
        const std::uint64_t start_offset = write_cursor_;
        if (bytes.empty()) {
            return start_offset;
        }
#ifdef _WIN32
        LARGE_INTEGER pos{};
        pos.QuadPart = static_cast<LONGLONG>(start_offset);
        if (!::SetFilePointerEx(handle_, pos, nullptr, FILE_BEGIN)) {
            return make_error("failed to seek patch spillover workspace for write");
        }
        std::size_t written_total = 0;
        while (written_total < bytes.size()) {
            const std::size_t rem = bytes.size() - written_total;
            const auto chunk = static_cast<DWORD>(std::min<std::size_t>(rem, 16u * 1024u * 1024u));
            DWORD written = 0;
            if (!::WriteFile(handle_, bytes.data() + written_total, chunk, &written, nullptr) ||
                written == 0u) {
                return make_error("failed writing bytes to patch spillover workspace");
            }
            written_total += static_cast<std::size_t>(written);
        }
#else
        std::size_t written_total = 0;
        while (written_total < bytes.size()) {
            const std::size_t rem = bytes.size() - written_total;
            const ssize_t n = ::pwrite(
                fd_,
                bytes.data() + written_total,
                rem,
                static_cast<off_t>(start_offset + written_total));
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return make_error(std::format(
                    "failed writing bytes to patch spillover workspace: {}", std::strerror(errno)));
            }
            if (n == 0) {
                return make_error("zero-byte write to patch spillover workspace");
            }
            written_total += static_cast<std::size_t>(n);
        }
#endif
        write_cursor_ += static_cast<std::uint64_t>(bytes.size());
        bytes_written_atomic_.store(write_cursor_, std::memory_order_relaxed);
        return start_offset;
    }

    [[nodiscard]] Result<void> read_at(std::uint64_t offset, std::span<std::uint8_t> out) const {
        if (out.empty()) {
            return {};
        }
        std::scoped_lock lock(mutex_);
        if (offset > write_cursor_ || out.size() > write_cursor_ - offset) {
            return make_error("patch spillover read range exceeds workspace bounds");
        }
#ifdef _WIN32
        LARGE_INTEGER pos{};
        pos.QuadPart = static_cast<LONGLONG>(offset);
        if (!::SetFilePointerEx(handle_, pos, nullptr, FILE_BEGIN)) {
            return make_error("failed to seek patch spillover workspace for read");
        }
        std::size_t read_total = 0;
        while (read_total < out.size()) {
            const std::size_t rem = out.size() - read_total;
            const auto chunk = static_cast<DWORD>(std::min<std::size_t>(rem, 16u * 1024u * 1024u));
            DWORD got = 0;
            if (!::ReadFile(handle_, out.data() + read_total, chunk, &got, nullptr) || got == 0u) {
                return make_error("failed reading bytes from patch spillover workspace");
            }
            read_total += static_cast<std::size_t>(got);
        }
#else
        std::size_t read_total = 0;
        while (read_total < out.size()) {
            const std::size_t rem = out.size() - read_total;
            const ssize_t n = ::pread(
                fd_,
                out.data() + read_total,
                rem,
                static_cast<off_t>(offset + read_total));
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return make_error(std::format(
                    "failed reading bytes from patch spillover workspace: {}", std::strerror(errno)));
            }
            if (n == 0) {
                return make_error("unexpected EOF reading patch spillover workspace");
            }
            read_total += static_cast<std::size_t>(n);
        }
#endif
        return {};
    }

    [[nodiscard]] std::uint64_t bytes_written() const noexcept {
        return bytes_written_atomic_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] const std::filesystem::path& directory() const noexcept {
        return dir_;
    }

private:
#ifdef _WIN32
    PatchSpillWorkspace(std::filesystem::path dir, HANDLE handle) noexcept
        : handle_(handle), dir_(std::move(dir)) {}
    HANDLE handle_{INVALID_HANDLE_VALUE};
#else
    PatchSpillWorkspace(std::filesystem::path dir, int fd) noexcept
        : fd_(fd), dir_(std::move(dir)) {}
    int fd_{-1};
#endif
    std::filesystem::path dir_{};
    mutable std::mutex mutex_{};
    std::uint64_t write_cursor_{0};
    std::atomic<std::uint64_t> bytes_written_atomic_{0};
};

} // namespace detail

namespace {

[[nodiscard]] std::int64_t current_unix_timestamp_ms() noexcept {
    const auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
}

[[nodiscard]] bool add_overflows(std::uint64_t a, std::uint64_t b) noexcept {
    return a > std::numeric_limits<std::uint64_t>::max() - b;
}

[[nodiscard]] std::uint64_t span_end(std::uint64_t offset, std::uint64_t size) noexcept {
    return offset + size;
}

void rebuild_committed_interval_into(
    std::map<std::uint64_t, CommittedPatchInterval>& committed_map,
    const std::map<std::uint64_t, std::uint8_t>& original_ram,
    std::uint64_t address,
    std::span<const std::uint8_t> written_bytes) {
    if (written_bytes.empty()) {
        return;
    }

    std::uint64_t union_begin = address;
    std::uint64_t union_end = address + static_cast<std::uint64_t>(written_bytes.size());

    auto erase_begin = committed_map.lower_bound(address);
    if (erase_begin != committed_map.begin()) {
        auto prev = erase_begin;
        --prev;
        if (prev->second.end_address() >= address) {
            erase_begin = prev;
        }
    }

    auto erase_end = erase_begin;
    while (erase_end != committed_map.end() && erase_end->second.address <= union_end) {
        union_begin = std::min(union_begin, erase_end->second.address);
        union_end = std::max(union_end, erase_end->second.end_address());
        ++erase_end;
    }

    const auto union_len = static_cast<std::size_t>(union_end - union_begin);
    std::vector<std::uint8_t> orig(union_len, 0);
    std::vector<std::uint8_t> curr(union_len, 0);

    for (std::size_t i = 0; i < union_len; ++i) {
        const std::uint64_t va = union_begin + static_cast<std::uint64_t>(i);
        if (const auto it = original_ram.find(va); it != original_ram.end()) {
            orig[i] = it->second;
            curr[i] = it->second;
        }
    }

    for (auto it = erase_begin; it != erase_end; ++it) {
        const auto rel = static_cast<std::ptrdiff_t>(it->second.address - union_begin);
        std::copy(it->second.committed.begin(), it->second.committed.end(), curr.begin() + rel);
    }

    const auto write_rel = static_cast<std::ptrdiff_t>(address - union_begin);
    std::copy(written_bytes.begin(), written_bytes.end(), curr.begin() + write_rel);

    committed_map.erase(erase_begin, erase_end);

    std::size_t run_begin = 0;
    bool in_run = false;
    for (std::size_t i = 0; i < union_len; ++i) {
        const bool diff = curr[i] != orig[i];
        if (diff && !in_run) {
            run_begin = i;
            in_run = true;
        }
        const bool at_end = (i + 1 == union_len);
        if (in_run && (!diff || at_end)) {
            const std::size_t run_end = (diff && at_end) ? (i + 1) : i;
            CommittedPatchInterval ci;
            ci.address = union_begin + static_cast<std::uint64_t>(run_begin);
            ci.original.assign(orig.begin() + static_cast<std::ptrdiff_t>(run_begin),
                               orig.begin() + static_cast<std::ptrdiff_t>(run_end));
            ci.committed.assign(curr.begin() + static_cast<std::ptrdiff_t>(run_begin),
                                curr.begin() + static_cast<std::ptrdiff_t>(run_end));
            committed_map.emplace(ci.address, std::move(ci));
            in_run = false;
        }
    }
}

} // namespace

PatchTransaction::PatchTransaction(PagedBinaryImage& image, std::string label, std::string note)
    : image_(&image), label_(std::move(label)), note_(std::move(note)) {}

PatchTransaction& PatchTransaction::set_note(std::string note) {
    note_ = std::move(note);
    return *this;
}

Result<void> PatchTransaction::write(std::uint64_t offset,
                                     std::span<const std::uint8_t> bytes,
                                     std::string note) {
    if (committed_) {
        return make_error("cannot write to a committed patch transaction");
    }
    if (image_ == nullptr) {
        return make_error("patch transaction has no image");
    }
    if (bytes.empty()) {
        return {};
    }
    if (auto valid = image_->validate_range(offset, static_cast<std::uint64_t>(bytes.size())); !valid) {
        return std::unexpected(valid.error());
    }

    writes_.push_back(PendingPatchWrite{
        .offset = offset,
        .bytes = std::vector<std::uint8_t>(bytes.begin(), bytes.end()),
        .note = std::move(note),
    });
    return {};
}

Result<void> PatchTransaction::commit() {
    if (committed_) {
        return make_error("patch transaction already committed");
    }
    if (image_ == nullptr) {
        return make_error("patch transaction has no image");
    }

    auto applied = image_->apply_transaction(label_, note_, writes_);
    if (!applied) {
        return std::unexpected(applied.error());
    }

    committed_ = true;
    writes_.clear();
    return {};
}

void PatchTransaction::rollback() noexcept {
    writes_.clear();
    committed_ = true;
}

Result<void> PagedBinaryImage::StoredPatchPayload::read_into(
    std::uint64_t sub_offset,
    std::span<std::uint8_t> out) const {
    if (out.empty()) {
        return {};
    }
    if (sub_offset > byte_size || out.size() > byte_size - sub_offset) {
        return make_error("stored patch payload subrange out of bounds");
    }
    if (spill_ws != nullptr) {
        return spill_ws->read_at(spill_offset + sub_offset, out);
    }
    std::copy_n(inline_bytes.begin() + static_cast<std::ptrdiff_t>(sub_offset),
                static_cast<std::ptrdiff_t>(out.size()),
                out.begin());
    return {};
}

Result<std::vector<std::uint8_t>> PagedBinaryImage::StoredPatchPayload::materialize() const {
    std::vector<std::uint8_t> out(byte_size);
    if (byte_size == 0u) {
        return out;
    }
    if (auto rd = read_into(0u, out); !rd) {
        return std::unexpected(rd.error());
    }
    return out;
}

Result<void> PagedBinaryImage::ensure_spill_workspace() const {
    if (spill_workspace_ != nullptr) {
        return {};
    }
    auto ws = detail::PatchSpillWorkspace::create();
    if (!ws) {
        return std::unexpected(ws.error());
    }
    spill_workspace_ = std::move(*ws);
    return {};
}

Result<PagedBinaryImage::StoredPatchPayload> PagedBinaryImage::store_payload(
    std::span<const std::uint8_t> bytes) const {
    StoredPatchPayload payload;
    payload.byte_size = bytes.size();
    if (bytes.empty()) {
        return payload;
    }
    if (bytes.size() >= spillover_threshold_bytes_) {
        if (auto ok = ensure_spill_workspace(); !ok) {
            return std::unexpected(ok.error());
        }
        auto off = spill_workspace_->append(bytes);
        if (!off) {
            return std::unexpected(off.error());
        }
        payload.spill_ws = spill_workspace_;
        payload.spill_offset = *off;
        return payload;
    }
    payload.inline_bytes.assign(bytes.begin(), bytes.end());
    return payload;
}

Result<PatchInterval> PagedBinaryImage::materialize_interval(
    const StoredPatchInterval& stored) const {
    auto orig = stored.original.materialize();
    if (!orig) {
        return std::unexpected(orig.error());
    }
    auto pat = stored.patched.materialize();
    if (!pat) {
        return std::unexpected(pat.error());
    }
    PatchInterval out;
    out.offset = stored.offset;
    out.original = std::move(*orig);
    out.patched = std::move(*pat);
    out.timestamp_unix_ms = stored.timestamp_unix_ms;
    out.note = stored.note;
    return out;
}

std::uint64_t PagedBinaryImage::spilled_bytes_on_disk() const noexcept {
    return spill_workspace_ != nullptr ? spill_workspace_->bytes_written() : 0u;
}

std::size_t PagedBinaryImage::inline_patch_bytes_in_ram() const noexcept {
    std::size_t total = 0u;
    for (const auto& [off, iv] : patches_) {
        (void)off;
        total += iv.original.inline_bytes.size() + iv.patched.inline_bytes.size();
    }
    return total;
}

std::filesystem::path PagedBinaryImage::spillover_directory() const {
    if (spill_workspace_ != nullptr) {
        return spill_workspace_->directory();
    }
    return detail::resolve_guarded_spill_temp_dir();
}

Result<PagedBinaryImage> PagedBinaryImage::open(std::filesystem::path path, std::uint64_t page_size) {
    if (page_size == 0) {
        return make_error("page size must be greater than zero");
    }

    std::error_code ec;
    const bool exists = std::filesystem::exists(path, ec);
    if (ec || !exists) {
        return make_error("binary image file does not exist");
    }
    const auto size = std::filesystem::file_size(path, ec);
    if (ec) {
        return make_error("failed to query binary image file size");
    }

    PagedBinaryImage image;
    image.path_ = std::move(path);
    image.size_ = static_cast<std::uint64_t>(size);
    image.page_size_ = page_size;
    image.input_.open(image.path_, std::ios::binary);
    if (!image.input_) return make_error("failed to open binary image file");
    return image;
}

Result<void> PagedBinaryImage::validate_range(std::uint64_t offset, std::uint64_t size) const {
    if (add_overflows(offset, size)) {
        return make_error("binary image range overflows");
    }
    if (offset > size_ || span_end(offset, size) > size_) {
        return make_error("binary image range is outside the file");
    }
    return {};
}

Result<std::vector<std::uint8_t>> PagedBinaryImage::load_page(std::uint64_t page_index) const {
    const auto cached = page_cache_.find(page_index);
    if (cached != page_cache_.end()) {
        return cached->second;
    }

    const std::uint64_t offset = page_index * page_size_;
    if (offset >= size_) {
        return make_error("page index is outside the file");
    }
    const std::uint64_t remaining = size_ - offset;
    const std::uint64_t bytes_to_read = std::min(page_size_, remaining);

    auto& file = input_;
    file.clear();
    if (!file.is_open()) {
        return make_error("failed to open binary image file");
    }
    file.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!file) {
        return make_error("failed to seek binary image file");
    }

    std::vector<std::uint8_t> page(static_cast<std::size_t>(bytes_to_read));
    file.read(reinterpret_cast<char*>(page.data()), static_cast<std::streamsize>(page.size()));
    if (file.gcount() != static_cast<std::streamsize>(page.size())) {
        return make_error("failed to read binary image page");
    }

    // Bound retained pages to approximately 16 MiB (at least one page).
    const auto cache_limit = std::max<std::uint64_t>(1, (16u * 1024u * 1024u) / page_size_);
    if (page_cache_.size() >= cache_limit) page_cache_.erase(page_cache_.begin());
    auto [it, inserted] = page_cache_.try_emplace(page_index, std::move(page));
    (void)inserted;
    return it->second;
}

Result<std::vector<std::uint8_t>> PagedBinaryImage::read_file_range(std::uint64_t offset,
                                                                    std::uint64_t size) const {
    if (auto valid = validate_range(offset, size); !valid) {
        return std::unexpected(valid.error());
    }

    std::vector<std::uint8_t> result(static_cast<std::size_t>(size));
    std::uint64_t copied = 0;
    while (copied < size) {
        const std::uint64_t absolute = offset + copied;
        const std::uint64_t page_index = absolute / page_size_;
        const std::uint64_t page_offset = absolute % page_size_;
        auto page = load_page(page_index);
        if (!page) {
            return std::unexpected(page.error());
        }

        const std::uint64_t available_in_page =
            std::min<std::uint64_t>(static_cast<std::uint64_t>(page->size()) - page_offset, size - copied);
        std::copy_n(page->begin() + static_cast<std::ptrdiff_t>(page_offset),
                    static_cast<std::ptrdiff_t>(available_in_page),
                    result.begin() + static_cast<std::ptrdiff_t>(copied));
        copied += available_in_page;
    }

    return result;
}

Result<std::vector<std::uint8_t>> PagedBinaryImage::read_original(std::uint64_t offset,
                                                                  std::uint64_t size) const {
    auto bytes = read_file_range(offset, size);
    if (!bytes || size == 0 || patches_.empty()) {
        return bytes;
    }

    const std::uint64_t end = span_end(offset, size);
    auto it = patches_.upper_bound(offset);
    if (it != patches_.begin()) {
        --it;
    }

    for (; it != patches_.end(); ++it) {
        const StoredPatchInterval& patch = it->second;
        if (patch.offset >= end) {
            break;
        }
        if (patch.end_offset() <= offset) {
            continue;
        }

        const std::uint64_t copy_begin = std::max(offset, patch.offset);
        const std::uint64_t copy_end = std::min(end, patch.end_offset());
        const std::uint64_t patch_start = copy_begin - patch.offset;
        const std::uint64_t output_start = copy_begin - offset;
        const std::uint64_t copy_size = copy_end - copy_begin;
        auto dst = std::span<std::uint8_t>(
            bytes->data() + static_cast<std::size_t>(output_start),
            static_cast<std::size_t>(copy_size));
        if (auto rd = patch.original.read_into(patch_start, dst); !rd) {
            return std::unexpected(rd.error());
        }
    }

    return bytes;
}

Result<std::vector<std::uint8_t>> PagedBinaryImage::read_effective(std::uint64_t offset,
                                                                   std::uint64_t size) const {
    auto bytes = read_file_range(offset, size);
    if (!bytes) {
        return bytes;
    }
    if (size == 0) {
        return bytes;
    }

    const std::uint64_t end = span_end(offset, size);
    auto it = patches_.upper_bound(offset);
    if (it != patches_.begin()) {
        --it;
    }

    for (; it != patches_.end(); ++it) {
        const StoredPatchInterval& patch = it->second;
        if (patch.offset >= end) {
            break;
        }
        if (patch.end_offset() <= offset) {
            continue;
        }

        const std::uint64_t copy_begin = std::max(offset, patch.offset);
        const std::uint64_t copy_end = std::min(end, patch.end_offset());
        const std::uint64_t patch_start = copy_begin - patch.offset;
        const std::uint64_t output_start = copy_begin - offset;
        const std::uint64_t copy_size = copy_end - copy_begin;
        auto dst = std::span<std::uint8_t>(
            bytes->data() + static_cast<std::size_t>(output_start),
            static_cast<std::size_t>(copy_size));
        if (auto rd = patch.patched.read_into(patch_start, dst); !rd) {
            return std::unexpected(rd.error());
        }
    }

    return bytes;
}

std::vector<PatchInterval> PagedBinaryImage::changed_intervals() const {
    std::vector<PatchInterval> result;
    result.reserve(patches_.size());
    for (const auto& [offset, patch] : patches_) {
        (void)offset;
        if (auto mat = materialize_interval(patch); mat.has_value()) {
            result.push_back(std::move(*mat));
        }
    }
    return result;
}

bool PagedBinaryImage::is_patched(std::uint64_t offset) const noexcept {
    if (offset >= size_ || patches_.empty()) {
        return false;
    }
    auto it = patches_.upper_bound(offset);
    if (it == patches_.begin()) {
        return false;
    }
    --it;
    const StoredPatchInterval& patch = it->second;
    return offset >= patch.offset &&
           (offset - patch.offset) < static_cast<std::uint64_t>(patch.patched.size());
}

std::vector<PatchInterval> PagedBinaryImage::changed_intervals(std::uint64_t offset,
                                                               std::uint64_t size) const {
    std::vector<PatchInterval> result;
    if (validate_range(offset, size).has_value() == false || size == 0) {
        return result;
    }

    const std::uint64_t end = span_end(offset, size);
    auto it = patches_.upper_bound(offset);
    if (it != patches_.begin()) {
        --it;
    }
    for (; it != patches_.end(); ++it) {
        const StoredPatchInterval& patch = it->second;
        if (patch.offset >= end) {
            break;
        }
        if (patch.end_offset() > offset) {
            if (auto mat = materialize_interval(patch); mat.has_value()) {
                result.push_back(std::move(*mat));
            }
        }
    }
    return result;
}

std::vector<PatchTransactionMetadata> PagedBinaryImage::undo_history() const {
    std::vector<PatchTransactionMetadata> history;
    history.reserve(undo_stack_.size());
    for (const auto& tx_edits : undo_stack_) {
        if (tx_edits.empty()) {
            continue;
        }
        PatchTransactionMetadata meta;
        meta.label = tx_edits.front().label;
        meta.timestamp_unix_ms = tx_edits.front().timestamp_unix_ms;
        meta.edit_count = tx_edits.size();
        for (const StoredPatchEdit& e : tx_edits) {
            meta.total_bytes += static_cast<std::uint64_t>(e.after.size());
            if (meta.note.empty() && !e.note.empty()) {
                meta.note = e.note;
            }
        }
        history.push_back(std::move(meta));
    }
    return history;
}

std::optional<PatchTransactionMetadata> PagedBinaryImage::last_commit_metadata() const {
    if (undo_stack_.empty() || undo_stack_.back().empty()) {
        return std::nullopt;
    }
    const auto& tx_edits = undo_stack_.back();
    PatchTransactionMetadata meta;
    meta.label = tx_edits.front().label;
    meta.timestamp_unix_ms = tx_edits.front().timestamp_unix_ms;
    meta.edit_count = tx_edits.size();
    for (const StoredPatchEdit& e : tx_edits) {
        meta.total_bytes += static_cast<std::uint64_t>(e.after.size());
        if (meta.note.empty() && !e.note.empty()) {
            meta.note = e.note;
        }
    }
    return meta;
}

PatchTransaction PagedBinaryImage::begin_transaction(std::string label, std::string note) {
    return PatchTransaction(*this, std::move(label), std::move(note));
}

Result<void> PagedBinaryImage::apply_replacement_no_history(std::uint64_t offset,
                                                            std::span<const std::uint8_t> bytes,
                                                            std::int64_t timestamp_unix_ms,
                                                            std::string_view note) {
    if (bytes.empty()) {
        return {};
    }
    if (auto valid = validate_range(offset, static_cast<std::uint64_t>(bytes.size())); !valid) {
        return std::unexpected(valid.error());
    }

    const std::uint64_t write_begin = offset;
    const std::uint64_t write_end = offset + static_cast<std::uint64_t>(bytes.size());
    std::uint64_t union_begin = write_begin;
    std::uint64_t union_end = write_end;

    auto erase_begin = patches_.lower_bound(offset);
    if (erase_begin != patches_.begin()) {
        auto previous = erase_begin;
        --previous;
        if (previous->second.end_offset() >= offset) {
            erase_begin = previous;
        }
    }

    struct PriorMetaSpan {
        std::uint64_t begin{};
        std::uint64_t end{};
        std::int64_t timestamp_unix_ms{0};
        std::string note{};
    };
    std::vector<PriorMetaSpan> prior_meta;

    auto erase_end = erase_begin;
    while (erase_end != patches_.end() && erase_end->second.offset <= union_end) {
        union_begin = std::min(union_begin, erase_end->second.offset);
        union_end = std::max(union_end, erase_end->second.end_offset());
        prior_meta.push_back(PriorMetaSpan{
            .begin = erase_end->second.offset,
            .end = erase_end->second.end_offset(),
            .timestamp_unix_ms = erase_end->second.timestamp_unix_ms,
            .note = erase_end->second.note,
        });
        ++erase_end;
    }

    auto original = read_original(union_begin, union_end - union_begin);
    if (!original) {
        return std::unexpected(original.error());
    }
    auto patched = read_effective(union_begin, union_end - union_begin);
    if (!patched) {
        return std::unexpected(patched.error());
    }

    std::copy(bytes.begin(),
              bytes.end(),
              patched->begin() + static_cast<std::ptrdiff_t>(offset - union_begin));

    patches_.erase(erase_begin, erase_end);

    std::uint64_t run_begin = 0;
    bool in_run = false;
    for (std::uint64_t index = 0; index < static_cast<std::uint64_t>(patched->size()); ++index) {
        const bool changed = (*patched)[static_cast<std::size_t>(index)] !=
                             (*original)[static_cast<std::size_t>(index)];
        if (changed && !in_run) {
            run_begin = index;
            in_run = true;
        }
        const bool at_end = index + 1 == static_cast<std::uint64_t>(patched->size());
        if (in_run && (!changed || at_end)) {
            const std::uint64_t run_end = changed && at_end ? index + 1 : index;
            const std::uint64_t abs_begin = union_begin + run_begin;
            const std::uint64_t abs_end = union_begin + run_end;
            const auto run_len = static_cast<std::size_t>(run_end - run_begin);

            auto orig_payload = store_payload(std::span<const std::uint8_t>(
                original->data() + static_cast<std::size_t>(run_begin), run_len));
            if (!orig_payload) {
                return std::unexpected(orig_payload.error());
            }
            auto patched_payload = store_payload(std::span<const std::uint8_t>(
                patched->data() + static_cast<std::size_t>(run_begin), run_len));
            if (!patched_payload) {
                return std::unexpected(patched_payload.error());
            }

            StoredPatchInterval interval;
            interval.offset = abs_begin;
            interval.original = std::move(*orig_payload);
            interval.patched = std::move(*patched_payload);

            const bool overlaps_write = (abs_begin < write_end) && (abs_end > write_begin);
            if (overlaps_write && (timestamp_unix_ms != 0 || !note.empty())) {
                interval.timestamp_unix_ms = timestamp_unix_ms;
                interval.note = std::string(note);
                if (interval.note.empty()) {
                    for (const PriorMetaSpan& pm : prior_meta) {
                        if (pm.begin < abs_end && pm.end > abs_begin && !pm.note.empty()) {
                            interval.note = pm.note;
                            break;
                        }
                    }
                }
            } else {
                for (const PriorMetaSpan& pm : prior_meta) {
                    if (pm.begin < abs_end && pm.end > abs_begin) {
                        interval.timestamp_unix_ms = pm.timestamp_unix_ms;
                        interval.note = pm.note;
                        break;
                    }
                }
            }

            patches_.emplace(interval.offset, std::move(interval));
            in_run = false;
        }
    }

    return {};
}

Result<void> PagedBinaryImage::apply_transaction(std::string label,
                                                 std::string note,
                                                 std::span<const PendingPatchWrite> writes) {
    if (writes.empty()) {
        return {};
    }

    for (const auto& write : writes) {
        if (auto valid = validate_range(write.offset, write.bytes.size()); !valid)
            return std::unexpected(valid.error());
    }

    const std::int64_t commit_ts_ms = current_unix_timestamp_ms();

    // Retain sparse intervals for rollback; never snapshot gaps between writes.
    undo_stack_.reserve(undo_stack_.size() + 1);
    auto saved = patches_;
    std::vector<StoredPatchEdit> edits;
    edits.reserve(writes.size());
    try {
        for (const auto& write : writes) {
            auto before = read_effective(write.offset, write.bytes.size());
            if (!before) {
                patches_.swap(saved);
                return std::unexpected(before.error());
            }
            if (*before == write.bytes) continue;

            auto before_payload = store_payload(*before);
            if (!before_payload) {
                patches_.swap(saved);
                return std::unexpected(before_payload.error());
            }
            auto after_payload = store_payload(write.bytes);
            if (!after_payload) {
                patches_.swap(saved);
                return std::unexpected(after_payload.error());
            }

            std::string effective_note = !write.note.empty() ? write.note : note;
            auto applied = apply_replacement_no_history(
                write.offset, write.bytes, commit_ts_ms, effective_note);
            if (!applied) {
                patches_.swap(saved);
                return std::unexpected(applied.error());
            }
            edits.push_back(StoredPatchEdit{
                .offset = write.offset,
                .before = std::move(*before_payload),
                .after = std::move(*after_payload),
                .label = label,
                .timestamp_unix_ms = commit_ts_ms,
                .note = std::move(effective_note),
            });
        }
        if (!edits.empty()) {
            undo_stack_.push_back(std::move(edits));
            redo_stack_.clear();
        }
    } catch (...) {
        patches_.swap(saved);
        throw;
    }

    return {};
}

Result<void> PagedBinaryImage::apply_patch(std::uint64_t offset,
                                           std::span<const std::uint8_t> bytes,
                                           std::string label,
                                           std::string note) {
    auto tx = begin_transaction(std::move(label), std::move(note));
    if (auto written = tx.write(offset, bytes); !written) {
        return std::unexpected(written.error());
    }
    return tx.commit();
}

Result<void> PagedBinaryImage::undo() {
    if (undo_stack_.empty()) {
        return make_error("no patch edit to undo");
    }

    redo_stack_.reserve(redo_stack_.size() + 1);
    auto saved = patches_;
    try {
        // Reverse order is essential for overlapping writes in a transaction.
        for (auto it = undo_stack_.back().rbegin(); it != undo_stack_.back().rend(); ++it) {
            auto before_bytes = it->before.materialize();
            if (!before_bytes) {
                patches_.swap(saved);
                return std::unexpected(before_bytes.error());
            }
            std::int64_t restored_ts = 0;
            std::string restored_note;
            for (std::size_t idx = undo_stack_.size() - 1u; idx > 0u; --idx) {
                const auto& earlier_tx = undo_stack_[idx - 1u];
                bool found = false;
                for (auto eit = earlier_tx.rbegin(); eit != earlier_tx.rend(); ++eit) {
                    const std::uint64_t eb = eit->offset;
                    const std::uint64_t ee = eb + static_cast<std::uint64_t>(eit->after.size());
                    const std::uint64_t cb = it->offset;
                    const std::uint64_t ce = cb + static_cast<std::uint64_t>(it->before.size());
                    if (eb < ce && ee > cb) {
                        restored_ts = eit->timestamp_unix_ms;
                        restored_note = eit->note;
                        found = true;
                        break;
                    }
                }
                if (found) {
                    break;
                }
            }
            auto applied = apply_replacement_no_history(
                it->offset, *before_bytes, restored_ts, restored_note);
            if (!applied) {
                patches_.swap(saved);
                return std::unexpected(applied.error());
            }
        }
        redo_stack_.push_back(std::move(undo_stack_.back()));
        undo_stack_.pop_back();
    } catch (...) {
        patches_.swap(saved);
        throw;
    }
    return {};
}

Result<void> PagedBinaryImage::redo() {
    if (redo_stack_.empty()) return make_error("no patch edit to redo");
    undo_stack_.reserve(undo_stack_.size() + 1);
    auto saved = patches_;
    try {
        for (const auto& edit : redo_stack_.back()) {
            auto after_bytes = edit.after.materialize();
            if (!after_bytes) {
                patches_.swap(saved);
                return std::unexpected(after_bytes.error());
            }
            auto applied = apply_replacement_no_history(
                edit.offset, *after_bytes, edit.timestamp_unix_ms, edit.note);
            if (!applied) {
                patches_.swap(saved);
                return std::unexpected(applied.error());
            }
        }
        undo_stack_.push_back(std::move(redo_stack_.back()));
        redo_stack_.pop_back();
    } catch (...) {
        patches_.swap(saved);
        throw;
    }
    return {};
}

Result<void> PagedBinaryImage::save_as(const std::filesystem::path& output_path,
                                       bool overwrite) const {
    if (output_path.empty()) {
        return make_error("output path is empty");
    }

    std::error_code ec;
    const auto input_absolute = std::filesystem::weakly_canonical(path_, ec);
    const std::filesystem::path normalized_input =
        ec ? std::filesystem::absolute(path_) : input_absolute;
    ec.clear();
    const auto output_parent = output_path.parent_path();
    const std::filesystem::path output_base =
        output_parent.empty()
            ? std::filesystem::current_path(ec)
            : std::filesystem::weakly_canonical(output_parent, ec);
    if (ec) {
        return make_error("failed to resolve output directory");
    }
    const std::filesystem::path normalized_output = output_base / output_path.filename();

    ec.clear();
    const bool output_exists = std::filesystem::exists(output_path, ec);
    if (ec) {
        return make_error("failed to query output path");
    }

    std::error_code eq_ec;
    const bool same_file =
        (normalized_input == normalized_output) ||
        (output_exists && std::filesystem::equivalent(path_, output_path, eq_ec) && !eq_ec);

    if (same_file && !overwrite) {
        return make_error("refusing to overwrite the input file");
    }

    auto writer = detail::AtomicFileWriter::open(output_path, false);
    if (!writer) {
        return std::unexpected(writer.error());
    }

    std::uint64_t offset = 0;
    while (offset < size_) {
        const std::uint64_t chunk_size = std::min<std::uint64_t>(page_size_, size_ - offset);
        auto bytes = read_effective(offset, chunk_size);
        if (!bytes) {
            return std::unexpected(bytes.error());
        }
        if (auto wr = writer->write(*bytes); !wr) {
            return wr;
        }
        offset += chunk_size;
    }

    if (auto flushed = writer->flush_and_close(); !flushed) {
        return flushed;
    }

    const bool reopen_backing_stream = same_file && input_.is_open();
    if (reopen_backing_stream) {
        input_.close();
    }

    if (auto committed = writer->commit(overwrite); !committed) {
        if (reopen_backing_stream) {
            input_.clear();
            input_.open(path_, std::ios::binary);
        }
        return committed;
    }

    std::error_code post_eq_ec;
    const bool backing_replaced =
        (normalized_input == normalized_output) ||
        (std::filesystem::equivalent(path_, output_path, post_eq_ec) && !post_eq_ec);

    if (backing_replaced) {
        page_cache_.clear();
        patches_.clear();
    }
    if (reopen_backing_stream || backing_replaced) {
        input_.clear();
        input_.open(path_, std::ios::binary);
        if (!input_) {
            return make_error("failed to reopen binary image file after overwrite");
        }
    }

    return {};
}

Result<void> PagedBinaryImage::write_effective_to(const std::filesystem::path& output_path,
                                                  bool overwrite) const {
    return save_as(output_path, overwrite);
}

// =============================================================================
// LiveMemoryPatchSpace
// =============================================================================

void LiveMemoryPatchSpace::clear() noexcept {
    original_ram_.clear();
    staged_.clear();
    committed_.clear();
    undo_stack_.clear();
    redo_stack_.clear();
}

void LiveMemoryPatchSpace::clear_staged() noexcept {
    staged_.clear();
    undo_stack_.clear();
    redo_stack_.clear();
}

bool LiveMemoryPatchSpace::is_staged(std::uint64_t address) const noexcept {
    if (staged_.empty()) {
        return false;
    }
    auto it = staged_.upper_bound(address);
    if (it == staged_.begin()) {
        return false;
    }
    --it;
    const PatchInterval& patch = it->second;
    return address >= patch.offset &&
           (address - patch.offset) < static_cast<std::uint64_t>(patch.patched.size());
}

bool LiveMemoryPatchSpace::is_committed(std::uint64_t address) const noexcept {
    if (committed_.empty()) {
        return false;
    }
    auto it = committed_.upper_bound(address);
    if (it == committed_.begin()) {
        return false;
    }
    --it;
    const CommittedPatchInterval& ci = it->second;
    return address >= ci.address &&
           (address - ci.address) < static_cast<std::uint64_t>(ci.committed.size());
}

LiveByteState LiveMemoryPatchSpace::byte_state_at(std::uint64_t address) const noexcept {
    if (is_staged(address)) {
        return LiveByteState::Staged;
    }
    if (is_committed(address)) {
        return LiveByteState::Committed;
    }
    return LiveByteState::Unmodified;
}

std::vector<PatchInterval> LiveMemoryPatchSpace::staged_intervals() const {
    std::vector<PatchInterval> out;
    out.reserve(staged_.size());
    for (const auto& [addr, interval] : staged_) {
        (void)addr;
        out.push_back(interval);
    }
    return out;
}

std::vector<PatchInterval> LiveMemoryPatchSpace::staged_intervals(std::uint64_t address,
                                                                  std::uint64_t size) const {
    std::vector<PatchInterval> out;
    if (size == 0 || add_overflows(address, size)) {
        return out;
    }
    const std::uint64_t end = address + size;
    auto it = staged_.lower_bound(address);
    if (it != staged_.begin()) {
        auto prev = it;
        --prev;
        if (prev->second.end_offset() > address) {
            it = prev;
        }
    }
    for (; it != staged_.end() && it->second.offset < end; ++it) {
        const std::uint64_t clip_begin = std::max(address, it->second.offset);
        const std::uint64_t clip_end = std::min(end, it->second.end_offset());
        if (clip_begin >= clip_end) {
            continue;
        }
        const auto rel_begin = static_cast<std::ptrdiff_t>(clip_begin - it->second.offset);
        const auto rel_end = static_cast<std::ptrdiff_t>(clip_end - it->second.offset);
        PatchInterval slice;
        slice.offset = clip_begin;
        slice.original.assign(it->second.original.begin() + rel_begin,
                              it->second.original.begin() + rel_end);
        slice.patched.assign(it->second.patched.begin() + rel_begin,
                             it->second.patched.begin() + rel_end);
        out.push_back(std::move(slice));
    }
    return out;
}

std::vector<CommittedPatchInterval> LiveMemoryPatchSpace::committed_intervals() const {
    std::vector<CommittedPatchInterval> out;
    out.reserve(committed_.size());
    for (const auto& [addr, interval] : committed_) {
        (void)addr;
        out.push_back(interval);
    }
    return out;
}

Result<std::vector<std::uint8_t>> LiveMemoryPatchSpace::read_live_baseline(
    IProcessSession& session,
    std::uint64_t address,
    std::size_t size) const {
    if (size == 0) {
        return std::vector<std::uint8_t>{};
    }
    if (add_overflows(address, static_cast<std::uint64_t>(size))) {
        return make_error("live memory address range overflows");
    }

    std::vector<std::uint8_t> out(size, 0);
    std::size_t offset = 0;
    while (offset < size) {
        auto span = std::span<std::uint8_t>(out.data() + offset, size - offset);
        auto got = session.read_memory(address + static_cast<std::uint64_t>(offset), span);
        if (!got || *got == 0) {
            return make_error(got ? "short read on target process memory"
                                  : std::string(got.error().message));
        }
        offset += *got;
    }
    return out;
}

Result<void> LiveMemoryPatchSpace::record_original_ram_if_missing(IProcessSession& session,
                                                                  std::uint64_t address,
                                                                  std::size_t size) {
    if (size == 0) {
        return {};
    }
    bool missing_any = false;
    for (std::size_t i = 0; i < size; ++i) {
        if (!original_ram_.contains(address + static_cast<std::uint64_t>(i))) {
            missing_any = true;
            break;
        }
    }
    if (!missing_any) {
        return {};
    }

    auto current = read_live_baseline(session, address, size);
    if (!current) {
        return std::unexpected(current.error());
    }
    for (std::size_t i = 0; i < size; ++i) {
        original_ram_.try_emplace(address + static_cast<std::uint64_t>(i), (*current)[i]);
    }
    return {};
}

Result<std::vector<std::uint8_t>> LiveMemoryPatchSpace::read_effective(
    IProcessSession& session,
    std::uint64_t address,
    std::size_t size) const {
    auto result = read_live_baseline(session, address, size);
    if (!result || size == 0) {
        return result;
    }

    const std::uint64_t end = address + static_cast<std::uint64_t>(size);
    auto it = staged_.lower_bound(address);
    if (it != staged_.begin()) {
        auto prev = it;
        --prev;
        if (prev->second.end_offset() > address) {
            it = prev;
        }
    }
    for (; it != staged_.end() && it->second.offset < end; ++it) {
        const std::uint64_t clip_begin = std::max(address, it->second.offset);
        const std::uint64_t clip_end = std::min(end, it->second.end_offset());
        if (clip_begin >= clip_end) {
            continue;
        }
        const auto src_off = static_cast<std::ptrdiff_t>(clip_begin - it->second.offset);
        const auto dst_off = static_cast<std::ptrdiff_t>(clip_begin - address);
        const auto len = static_cast<std::ptrdiff_t>(clip_end - clip_begin);
        std::copy_n(it->second.patched.begin() + src_off, len, result->begin() + dst_off);
    }

    return result;
}

void LiveMemoryPatchSpace::apply_overlay(std::uint64_t address,
                                         MemorySample& sample,
                                         std::vector<LiveByteState>* out_states) const {
    const std::size_t size = sample.bytes.size();
    if (out_states != nullptr) {
        out_states->assign(size, LiveByteState::Unmodified);
    }
    if (size == 0 || add_overflows(address, static_cast<std::uint64_t>(size))) {
        return;
    }

    const std::uint64_t end = address + static_cast<std::uint64_t>(size);

    if (out_states != nullptr && !committed_.empty()) {
        auto cit = committed_.lower_bound(address);
        if (cit != committed_.begin()) {
            auto prev = cit;
            --prev;
            if (prev->second.end_address() > address) {
                cit = prev;
            }
        }
        for (; cit != committed_.end() && cit->second.address < end; ++cit) {
            const std::uint64_t clip_begin = std::max(address, cit->second.address);
            const std::uint64_t clip_end = std::min(end, cit->second.end_address());
            for (std::uint64_t va = clip_begin; va < clip_end; ++va) {
                (*out_states)[static_cast<std::size_t>(va - address)] = LiveByteState::Committed;
            }
        }
    }

    if (staged_.empty()) {
        return;
    }

    auto sit = staged_.lower_bound(address);
    if (sit != staged_.begin()) {
        auto prev = sit;
        --prev;
        if (prev->second.end_offset() > address) {
            sit = prev;
        }
    }
    for (; sit != staged_.end() && sit->second.offset < end; ++sit) {
        const std::uint64_t clip_begin = std::max(address, sit->second.offset);
        const std::uint64_t clip_end = std::min(end, sit->second.end_offset());
        for (std::uint64_t va = clip_begin; va < clip_end; ++va) {
            const auto dst_idx = static_cast<std::size_t>(va - address);
            const auto src_idx = static_cast<std::size_t>(va - sit->second.offset);
            sample.bytes[dst_idx] = sit->second.patched[src_idx];
            if (dst_idx < sample.valid.size() && sample.valid[dst_idx] == 0) {
                sample.valid[dst_idx] = 1;
                ++sample.readable_count;
            }
            if (out_states != nullptr) {
                (*out_states)[dst_idx] = LiveByteState::Staged;
            }
        }
    }
}

Result<void> LiveMemoryPatchSpace::apply_staged_replacement_no_history(
    IProcessSession& session,
    std::uint64_t address,
    std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) {
        return {};
    }
    if (add_overflows(address, static_cast<std::uint64_t>(bytes.size()))) {
        return make_error("live patch range overflows");
    }

    std::uint64_t union_begin = address;
    std::uint64_t union_end = address + static_cast<std::uint64_t>(bytes.size());

    auto erase_begin = staged_.lower_bound(address);
    if (erase_begin != staged_.begin()) {
        auto prev = erase_begin;
        --prev;
        if (prev->second.end_offset() >= address) {
            erase_begin = prev;
        }
    }

    auto erase_end = erase_begin;
    while (erase_end != staged_.end() && erase_end->second.offset <= union_end) {
        union_begin = std::min(union_begin, erase_end->second.offset);
        union_end = std::max(union_end, erase_end->second.end_offset());
        ++erase_end;
    }

    const auto union_len = static_cast<std::size_t>(union_end - union_begin);
    if (auto orig_ok = record_original_ram_if_missing(session, union_begin, union_len); !orig_ok) {
        return std::unexpected(orig_ok.error());
    }

    auto baseline = read_live_baseline(session, union_begin, union_len);
    if (!baseline) {
        return std::unexpected(baseline.error());
    }
    auto effective = read_effective(session, union_begin, union_len);
    if (!effective) {
        return std::unexpected(effective.error());
    }

    std::copy(bytes.begin(),
              bytes.end(),
              effective->begin() + static_cast<std::ptrdiff_t>(address - union_begin));

    staged_.erase(erase_begin, erase_end);

    std::size_t run_begin = 0;
    bool in_run = false;
    for (std::size_t index = 0; index < effective->size(); ++index) {
        const bool changed = (*effective)[index] != (*baseline)[index];
        if (changed && !in_run) {
            run_begin = index;
            in_run = true;
        }
        const bool at_end = (index + 1 == effective->size());
        if (in_run && (!changed || at_end)) {
            const std::size_t run_end = (changed && at_end) ? (index + 1) : index;
            PatchInterval interval;
            interval.offset = union_begin + static_cast<std::uint64_t>(run_begin);
            interval.original.assign(baseline->begin() + static_cast<std::ptrdiff_t>(run_begin),
                                     baseline->begin() + static_cast<std::ptrdiff_t>(run_end));
            interval.patched.assign(effective->begin() + static_cast<std::ptrdiff_t>(run_begin),
                                    effective->begin() + static_cast<std::ptrdiff_t>(run_end));
            staged_.emplace(interval.offset, std::move(interval));
            in_run = false;
        }
    }

    return {};
}

Result<void> LiveMemoryPatchSpace::stage_writes(IProcessSession& session,
                                                std::span<const PendingPatchWrite> writes,
                                                std::string label) {
    if (writes.empty()) {
        return {};
    }

    struct Range {
        std::uint64_t begin{0};
        std::uint64_t end{0};
    };
    std::vector<Range> ranges;
    ranges.reserve(writes.size());
    for (const auto& w : writes) {
        if (w.bytes.empty()) {
            continue;
        }
        if (add_overflows(w.offset, static_cast<std::uint64_t>(w.bytes.size()))) {
            return make_error("live patch write overflows address space");
        }
        ranges.push_back(Range{w.offset, w.offset + static_cast<std::uint64_t>(w.bytes.size())});
    }
    if (ranges.empty()) {
        return {};
    }

    std::ranges::sort(ranges, [](const Range& a, const Range& b) { return a.begin < b.begin; });

    std::vector<Range> merged;
    merged.reserve(ranges.size());
    for (const Range& r : ranges) {
        if (merged.empty() || r.begin > merged.back().end) {
            merged.push_back(r);
        } else {
            merged.back().end = std::max(merged.back().end, r.end);
        }
    }

    std::vector<PatchSpanSnapshot> snapshots;
    snapshots.reserve(merged.size());
    for (const Range& r : merged) {
        auto before = read_effective(session, r.begin, static_cast<std::size_t>(r.end - r.begin));
        if (!before) {
            return std::unexpected(before.error());
        }
        snapshots.push_back(PatchSpanSnapshot{r.begin, std::move(*before), {}});
    }

    undo_stack_.reserve(undo_stack_.size() + 1);
    auto saved_staged = staged_;
    auto saved_orig = original_ram_;
    try {
        for (const auto& w : writes) {
            if (auto applied = apply_staged_replacement_no_history(session, w.offset, w.bytes);
                !applied) {
                staged_.swap(saved_staged);
                original_ram_.swap(saved_orig);
                return std::unexpected(applied.error());
            }
        }

        std::vector<PatchSpanSnapshot> changed;
        changed.reserve(snapshots.size());
        for (PatchSpanSnapshot& snap : snapshots) {
            auto after = read_effective(session, snap.offset, snap.before.size());
            if (!after) {
                staged_.swap(saved_staged);
                original_ram_.swap(saved_orig);
                return std::unexpected(after.error());
            }
            if (snap.before != *after) {
                snap.after = std::move(*after);
                changed.push_back(std::move(snap));
            }
        }

        if (!changed.empty()) {
            PatchEdit edit;
            edit.label = std::move(label);
            if (changed.size() == 1) {
                edit.offset = changed.front().offset;
                edit.before = changed.front().before;
                edit.after = changed.front().after;
            }
            edit.spans = std::move(changed);
            undo_stack_.push_back(std::move(edit));
            redo_stack_.clear();
        }
    } catch (...) {
        staged_.swap(saved_staged);
        original_ram_.swap(saved_orig);
        throw;
    }

    return {};
}

Result<void> LiveMemoryPatchSpace::stage_patch(IProcessSession& session,
                                               std::uint64_t address,
                                               std::span<const std::uint8_t> bytes,
                                               std::string label) {
    if (bytes.empty()) {
        return {};
    }
    PendingPatchWrite single{address, std::vector<std::uint8_t>(bytes.begin(), bytes.end())};
    return stage_writes(session, std::span<const PendingPatchWrite>(&single, 1), std::move(label));
}

Result<void> LiveMemoryPatchSpace::undo(IProcessSession& session) {
    if (undo_stack_.empty()) {
        return make_error("no staged patch to undo");
    }
    redo_stack_.reserve(redo_stack_.size() + 1);
    auto saved_staged = staged_;
    auto saved_orig = original_ram_;
    try {
        const PatchEdit& edit = undo_stack_.back();
        for (auto it = edit.spans.rbegin(); it != edit.spans.rend(); ++it) {
            if (auto applied = apply_staged_replacement_no_history(session, it->offset, it->before);
                !applied) {
                staged_.swap(saved_staged);
                original_ram_.swap(saved_orig);
                return std::unexpected(applied.error());
            }
        }
        redo_stack_.push_back(std::move(undo_stack_.back()));
        undo_stack_.pop_back();
    } catch (...) {
        staged_.swap(saved_staged);
        original_ram_.swap(saved_orig);
        throw;
    }
    return {};
}

Result<void> LiveMemoryPatchSpace::redo(IProcessSession& session) {
    if (redo_stack_.empty()) {
        return make_error("no staged patch to redo");
    }
    undo_stack_.reserve(undo_stack_.size() + 1);
    auto saved_staged = staged_;
    auto saved_orig = original_ram_;
    try {
        const PatchEdit& edit = redo_stack_.back();
        for (const PatchSpanSnapshot& snap : edit.spans) {
            if (auto applied = apply_staged_replacement_no_history(session, snap.offset, snap.after);
                !applied) {
                staged_.swap(saved_staged);
                original_ram_.swap(saved_orig);
                return std::unexpected(applied.error());
            }
        }
        undo_stack_.push_back(std::move(redo_stack_.back()));
        redo_stack_.pop_back();
    } catch (...) {
        staged_.swap(saved_staged);
        original_ram_.swap(saved_orig);
        throw;
    }
    return {};
}

void LiveMemoryPatchSpace::rebuild_committed_interval_for_range(
    std::uint64_t address,
    std::span<const std::uint8_t> written_bytes) {
    rebuild_committed_interval_into(committed_, original_ram_, address, written_bytes);
}

Result<std::size_t> LiveMemoryPatchSpace::commit_to_process(IProcessSession& session,
                                                            MemoryWriteOptions options) {
    if (staged_.empty()) {
        return std::size_t{0};
    }

    struct WritePlan {
        std::uint64_t address{0};
        std::vector<std::uint8_t> pre_write_live;
        std::span<const std::uint8_t> patched;
    };

    // Snapshot every target interval's current live bytes and prepare map updates
    // up front so neither allocation failure nor partial/failed write_memory leaves
    // target RAM or tracking maps inconsistent.
    auto next_orig = original_ram_;
    std::vector<WritePlan> plans;
    plans.reserve(staged_.size());
    for (const auto& [addr, interval] : staged_) {
        auto current = read_live_baseline(session, addr, interval.patched.size());
        if (!current) {
            return std::unexpected(current.error());
        }
        for (std::size_t i = 0; i < interval.patched.size(); ++i) {
            next_orig.try_emplace(addr + static_cast<std::uint64_t>(i), (*current)[i]);
        }
        plans.push_back(WritePlan{
            .address = addr,
            .pre_write_live = std::move(*current),
            .patched = interval.patched,
        });
    }

    auto next_committed = committed_;
    for (const auto& [addr, interval] : staged_) {
        rebuild_committed_interval_into(next_committed, next_orig, addr, interval.patched);
    }

    std::size_t total_bytes = 0;
    for (std::size_t idx = 0; idx < plans.size(); ++idx) {
        const WritePlan& plan = plans[idx];
        auto write_res = session.write_memory(plan.address, plan.patched, options);
        if (!write_res || *write_res != plan.patched.size()) {
            // Roll back any bytes touched in the current interval, then all previously applied intervals.
            const std::size_t current_rollback_len =
                write_res ? std::min(*write_res, plan.pre_write_live.size())
                          : plan.pre_write_live.size();
            if (current_rollback_len > 0u) {
                (void)session.write_memory(
                    plan.address,
                    std::span<const std::uint8_t>(plan.pre_write_live).first(current_rollback_len),
                    options);
            }
            for (std::size_t rev = idx; rev-- > 0u;) {
                (void)session.write_memory(plans[rev].address, plans[rev].pre_write_live, options);
            }
            return make_error(write_res ? "partial write while committing patch to process memory"
                                        : std::string(write_res.error().message));
        }

        total_bytes += plan.patched.size();
    }

    original_ram_.swap(next_orig);
    committed_.swap(next_committed);
    staged_.clear();
    undo_stack_.clear();
    redo_stack_.clear();
    return total_bytes;
}

Result<std::size_t> LiveMemoryPatchSpace::revert_committed(IProcessSession& session,
                                                           MemoryWriteOptions options) {
    if (committed_.empty()) {
        return std::size_t{0};
    }

    struct RevertedSpan {
        std::uint64_t address{0};
        const std::vector<std::uint8_t>* committed_bytes{nullptr};
    };

    std::vector<RevertedSpan> reverted;
    reverted.reserve(committed_.size());
    std::size_t total_reverted = 0;
    for (const auto& [addr, interval] : committed_) {
        auto write_res = session.write_memory(addr, interval.original, options);
        if (!write_res || *write_res != interval.original.size()) {
            const std::size_t current_rollback_len =
                write_res ? std::min(*write_res, interval.committed.size())
                          : interval.committed.size();
            if (current_rollback_len > 0u) {
                (void)session.write_memory(
                    addr,
                    std::span<const std::uint8_t>(interval.committed).first(current_rollback_len),
                    options);
            }
            for (auto it = reverted.rbegin(); it != reverted.rend(); ++it) {
                (void)session.write_memory(it->address, *it->committed_bytes, options);
            }
            return make_error(write_res ? "partial write while reverting committed RAM patch"
                                        : std::string(write_res.error().message));
        }
        reverted.push_back(RevertedSpan{addr, &interval.committed});
        total_reverted += interval.original.size();
    }

    committed_.clear();
    original_ram_.clear();
    staged_.clear();
    undo_stack_.clear();
    redo_stack_.clear();
    return total_reverted;
}

Result<void> LiveMemoryPatchSpace::revert_committed_interval(IProcessSession& session,
                                                             std::uint64_t address,
                                                             std::uint64_t size,
                                                             MemoryWriteOptions options) {
    if (size == 0) {
        return {};
    }
    if (add_overflows(address, size)) {
        return make_error("revert address range overflows");
    }

    const auto len = static_cast<std::size_t>(size);
    std::vector<std::uint8_t> orig_bytes(len, 0);
    for (std::size_t i = 0; i < len; ++i) {
        const auto it = original_ram_.find(address + static_cast<std::uint64_t>(i));
        if (it == original_ram_.end()) {
            return make_error("no recorded original RAM snapshot for requested revert range");
        }
        orig_bytes[i] = it->second;
    }

    auto pre_revert = read_live_baseline(session, address, len);
    auto next_committed = committed_;
    rebuild_committed_interval_into(next_committed, original_ram_, address, orig_bytes);

    auto write_res = session.write_memory(address, orig_bytes, options);
    if (!write_res || *write_res != orig_bytes.size()) {
        if (pre_revert.has_value()) {
            const std::size_t current_rollback_len =
                write_res ? std::min(*write_res, pre_revert->size()) : pre_revert->size();
            if (current_rollback_len > 0u) {
                (void)session.write_memory(
                    address,
                    std::span<const std::uint8_t>(*pre_revert).first(current_rollback_len),
                    options);
            }
        }
        return make_error(write_res ? "partial write while reverting committed RAM interval"
                                    : std::string(write_res.error().message));
    }

    committed_.swap(next_committed);
    return {};
}

} // namespace peelf
