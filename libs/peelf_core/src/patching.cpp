#include "peelf/patching.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <format>
#include <fstream>
#include <limits>
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace peelf {
namespace {

[[nodiscard]] bool add_overflows(std::uint64_t a, std::uint64_t b) noexcept {
    return a > std::numeric_limits<std::uint64_t>::max() - b;
}

[[nodiscard]] std::uint64_t span_end(std::uint64_t offset, std::uint64_t size) noexcept {
    return offset + size;
}

struct TempFileGuard {
    std::filesystem::path path;
    bool active{true};

    explicit TempFileGuard(std::filesystem::path p) : path(std::move(p)) {}

    ~TempFileGuard() {
        if (active && !path.empty()) {
            std::error_code ec;
            std::filesystem::remove(path, ec);
        }
    }

    TempFileGuard(const TempFileGuard&) = delete;
    TempFileGuard& operator=(const TempFileGuard&) = delete;

    void release() noexcept { active = false; }
};

[[nodiscard]] std::uint64_t current_process_tag() noexcept {
#ifdef _WIN32
    return static_cast<std::uint64_t>(GetCurrentProcessId());
#else
    return static_cast<std::uint64_t>(::getpid());
#endif
}

[[nodiscard]] std::filesystem::path make_unique_sibling_temp_path(
    const std::filesystem::path& output_base,
    const std::filesystem::path& filename) {
    static std::atomic<std::uint64_t> counter{0};
    const std::uint64_t pid = current_process_tag();
    const std::filesystem::path base_name =
        filename.empty() ? std::filesystem::path("patched.bin") : filename;
    for (unsigned attempt = 0; attempt < 64u; ++attempt) {
        const auto ticks = static_cast<std::uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count());
        const std::uint64_t seq = ++counter;
        std::filesystem::path candidate = output_base / base_name;
        candidate += std::format(".{}-{}-{}.tmp", pid, ticks, seq);
        std::error_code ec;
        if (!std::filesystem::exists(candidate, ec) && !ec) {
            return candidate;
        }
    }
    std::filesystem::path fallback = output_base / base_name;
    fallback += std::format(".{}-{}.tmp", pid, ++counter);
    return fallback;
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

PatchTransaction::PatchTransaction(PagedBinaryImage& image, std::string label)
    : image_(&image), label_(std::move(label)) {}

Result<void> PatchTransaction::write(std::uint64_t offset, std::span<const std::uint8_t> bytes) {
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

    writes_.push_back(PendingPatchWrite{offset, std::vector<std::uint8_t>(bytes.begin(), bytes.end())});
    return {};
}

Result<void> PatchTransaction::commit() {
    if (committed_) {
        return make_error("patch transaction already committed");
    }
    if (image_ == nullptr) {
        return make_error("patch transaction has no image");
    }

    auto applied = image_->apply_transaction(label_, writes_);
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
        const PatchInterval& patch = it->second;
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
        std::copy_n(patch.original.begin() + static_cast<std::ptrdiff_t>(patch_start),
                    static_cast<std::ptrdiff_t>(copy_size),
                    bytes->begin() + static_cast<std::ptrdiff_t>(output_start));
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
        const PatchInterval& patch = it->second;
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
        std::copy_n(patch.patched.begin() + static_cast<std::ptrdiff_t>(patch_start),
                    static_cast<std::ptrdiff_t>(copy_size),
                    bytes->begin() + static_cast<std::ptrdiff_t>(output_start));
    }

    return bytes;
}

std::vector<PatchInterval> PagedBinaryImage::changed_intervals() const {
    std::vector<PatchInterval> result;
    result.reserve(patches_.size());
    for (const auto& [offset, patch] : patches_) {
        (void)offset;
        result.push_back(patch);
    }
    return result;
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
        const PatchInterval& patch = it->second;
        if (patch.offset >= end) {
            break;
        }
        if (patch.end_offset() > offset) {
            result.push_back(patch);
        }
    }
    return result;
}

PatchTransaction PagedBinaryImage::begin_transaction(std::string label) {
    return PatchTransaction(*this, std::move(label));
}

Result<void> PagedBinaryImage::apply_replacement_no_history(std::uint64_t offset,
                                                            std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) {
        return {};
    }
    if (auto valid = validate_range(offset, static_cast<std::uint64_t>(bytes.size())); !valid) {
        return std::unexpected(valid.error());
    }

    std::uint64_t union_begin = offset;
    std::uint64_t union_end = offset + static_cast<std::uint64_t>(bytes.size());

    auto erase_begin = patches_.lower_bound(offset);
    if (erase_begin != patches_.begin()) {
        auto previous = erase_begin;
        --previous;
        if (previous->second.end_offset() >= offset) {
            erase_begin = previous;
        }
    }

    auto erase_end = erase_begin;
    while (erase_end != patches_.end() && erase_end->second.offset <= union_end) {
        union_begin = std::min(union_begin, erase_end->second.offset);
        union_end = std::max(union_end, erase_end->second.end_offset());
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
            PatchInterval interval;
            interval.offset = union_begin + run_begin;
            interval.original.assign(original->begin() + static_cast<std::ptrdiff_t>(run_begin),
                                     original->begin() + static_cast<std::ptrdiff_t>(run_end));
            interval.patched.assign(patched->begin() + static_cast<std::ptrdiff_t>(run_begin),
                                    patched->begin() + static_cast<std::ptrdiff_t>(run_end));
            patches_.emplace(interval.offset, std::move(interval));
            in_run = false;
        }
    }

    return {};
}

Result<void> PagedBinaryImage::apply_transaction(std::string label,
                                                 std::span<const PendingPatchWrite> writes) {
    if (writes.empty()) {
        return {};
    }

    for (const auto& write : writes) {
        if (auto valid = validate_range(write.offset, write.bytes.size()); !valid)
            return std::unexpected(valid.error());
    }

    // Retain sparse intervals for rollback; never snapshot gaps between writes.
    undo_stack_.reserve(undo_stack_.size() + 1);
    auto saved = patches_;
    std::vector<PatchEdit> edits;
    edits.reserve(writes.size());
    try {
        for (const auto& write : writes) {
            auto before = read_effective(write.offset, write.bytes.size());
            if (!before) {
                patches_.swap(saved);
                return std::unexpected(before.error());
            }
            if (*before == write.bytes) continue;
            edits.push_back(PatchEdit{
                .offset = write.offset,
                .before = std::move(*before),
                .after = write.bytes,
                .label = label,
            });
            auto applied = apply_replacement_no_history(write.offset, write.bytes);
            if (!applied) {
                patches_.swap(saved);
                return std::unexpected(applied.error());
            }
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
                                           std::string label) {
    auto tx = begin_transaction(std::move(label));
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
            auto applied = apply_replacement_no_history(it->offset, it->before);
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
            auto applied = apply_replacement_no_history(edit.offset, edit.after);
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
    if (!overwrite && output_exists) {
        return make_error("output file already exists");
    }

    const std::filesystem::path temp_path =
        make_unique_sibling_temp_path(output_base, output_path.filename());
    TempFileGuard temp_guard{temp_path};

    {
        std::ofstream output(temp_path, std::ios::binary | std::ios::trunc);
        if (!output) {
            return make_error("failed to open temporary output file");
        }

        std::uint64_t offset = 0;
        while (offset < size_) {
            const std::uint64_t chunk_size = std::min<std::uint64_t>(page_size_, size_ - offset);
            auto bytes = read_effective(offset, chunk_size);
            if (!bytes) {
                return std::unexpected(bytes.error());
            }
            output.write(reinterpret_cast<const char*>(bytes->data()),
                         static_cast<std::streamsize>(bytes->size()));
            if (!output) {
                return make_error("failed to write output file");
            }
            offset += chunk_size;
        }

        output.flush();
        output.close();
        if (!output) {
            return make_error("failed to flush output file");
        }
    }

    const bool reopen_backing_stream = same_file && input_.is_open();
    if (reopen_backing_stream) {
        input_.close();
    }

    std::error_code replace_ec;
#ifdef _WIN32
    if (!MoveFileExW(temp_path.c_str(),
                     output_path.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        replace_ec = std::error_code(static_cast<int>(GetLastError()), std::system_category());
    }
#else
    std::filesystem::rename(temp_path, output_path, replace_ec);
#endif
    if (replace_ec) {
        if (reopen_backing_stream) {
            input_.clear();
            input_.open(path_, std::ios::binary);
        }
        return make_error("failed to replace output file");
    }

    temp_guard.release();

    if (same_file) {
        page_cache_.clear();
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

    // Stage all map/vector allocations into local copies before writing to target RAM
    // so neither allocation failure nor partial write_memory failure leaves state inconsistent.
    auto next_orig = original_ram_;
    for (const auto& [addr, interval] : staged_) {
        bool missing_any = false;
        for (std::size_t i = 0; i < interval.patched.size(); ++i) {
            if (!next_orig.contains(addr + static_cast<std::uint64_t>(i))) {
                missing_any = true;
                break;
            }
        }
        if (missing_any) {
            auto current = read_live_baseline(session, addr, interval.patched.size());
            if (!current) {
                return std::unexpected(current.error());
            }
            for (std::size_t i = 0; i < interval.patched.size(); ++i) {
                next_orig.try_emplace(addr + static_cast<std::uint64_t>(i), (*current)[i]);
            }
        }
    }

    auto next_committed = committed_;
    for (const auto& [addr, interval] : staged_) {
        rebuild_committed_interval_into(next_committed, next_orig, addr, interval.patched);
    }

    struct AppliedSpan {
        std::uint64_t address{0};
        const std::vector<std::uint8_t>* previous_live{nullptr};
    };

    std::vector<AppliedSpan> applied;
    applied.reserve(staged_.size());
    std::size_t total_bytes = 0;

    for (const auto& [addr, interval] : staged_) {
        auto write_res = session.write_memory(addr, interval.patched, options);
        if (!write_res || *write_res != interval.patched.size()) {
            // Best-effort rollback of any intervals already written in this transaction.
            for (auto it = applied.rbegin(); it != applied.rend(); ++it) {
                (void)session.write_memory(it->address, *it->previous_live, options);
            }
            return make_error(write_res ? "partial write while committing patch to process memory"
                                        : std::string(write_res.error().message));
        }

        applied.push_back(AppliedSpan{addr, &interval.original});
        total_bytes += interval.patched.size();
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

    auto next_committed = committed_;
    rebuild_committed_interval_into(next_committed, original_ram_, address, orig_bytes);

    auto write_res = session.write_memory(address, orig_bytes, options);
    if (!write_res || *write_res != orig_bytes.size()) {
        return make_error(write_res ? "partial write while reverting committed RAM interval"
                                    : std::string(write_res.error().message));
    }

    committed_.swap(next_committed);
    return {};
}

} // namespace peelf
