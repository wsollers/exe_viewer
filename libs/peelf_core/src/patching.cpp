#include "peelf/patching.hpp"

#include <algorithm>
#include <fstream>
#include <limits>
#include <random>
#include <system_error>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif
#include <utility>

namespace peelf {
namespace {

[[nodiscard]] bool add_overflows(std::uint64_t a, std::uint64_t b) noexcept {
    return a > std::numeric_limits<std::uint64_t>::max() - b;
}

[[nodiscard]] std::uint64_t span_end(std::uint64_t offset, std::uint64_t size) noexcept {
    return offset + size;
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

    std::ifstream file(path_, std::ios::binary);
    if (!file) {
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

    auto [it, inserted] = page_cache_.emplace(page_index, std::move(page));
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
    return read_file_range(offset, size);
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

    std::uint64_t edit_begin = writes.front().offset;
    std::uint64_t edit_end = writes.front().offset + static_cast<std::uint64_t>(writes.front().bytes.size());
    for (const auto& write : writes) {
        if (auto valid = validate_range(write.offset, static_cast<std::uint64_t>(write.bytes.size())); !valid) {
            return std::unexpected(valid.error());
        }
        edit_begin = std::min(edit_begin, write.offset);
        edit_end = std::max(edit_end, write.offset + static_cast<std::uint64_t>(write.bytes.size()));
    }

    auto before = read_effective(edit_begin, edit_end - edit_begin);
    if (!before) {
        return std::unexpected(before.error());
    }

    for (const auto& write : writes) {
        auto applied = apply_replacement_no_history(write.offset, write.bytes);
        if (!applied) {
            return std::unexpected(applied.error());
        }
    }

    auto after = read_effective(edit_begin, edit_end - edit_begin);
    if (!after) {
        return std::unexpected(after.error());
    }

    if (*before != *after) {
        undo_stack_.push_back(PatchEdit{edit_begin, std::move(*before), std::move(*after), std::move(label)});
        redo_stack_.clear();
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

    PatchEdit edit = std::move(undo_stack_.back());
    undo_stack_.pop_back();
    auto applied = apply_replacement_no_history(edit.offset, edit.before);
    if (!applied) {
        return std::unexpected(applied.error());
    }
    redo_stack_.push_back(std::move(edit));
    return {};
}

Result<void> PagedBinaryImage::redo() {
    if (redo_stack_.empty()) {
        return make_error("no patch edit to redo");
    }

    PatchEdit edit = std::move(redo_stack_.back());
    redo_stack_.pop_back();
    auto applied = apply_replacement_no_history(edit.offset, edit.after);
    if (!applied) {
        return std::unexpected(applied.error());
    }
    undo_stack_.push_back(std::move(edit));
    return {};
}

Result<void> PagedBinaryImage::write_effective_to(const std::filesystem::path& output_path,
                                                   bool overwrite) const {
    if (output_path.empty() || output_path.filename().empty()) {
        return make_error("output path is empty or does not name a file");
    }

    std::error_code ec;
    const std::filesystem::path normalized_input = std::filesystem::weakly_canonical(path_, ec);
    if (ec) {
        return make_error("failed to resolve input file path");
    }

    const std::filesystem::path output_parent = output_path.has_parent_path()
        ? output_path.parent_path() : std::filesystem::current_path(ec);
    if (ec) {
        return make_error("failed to resolve working directory");
    }
    const std::filesystem::path normalized_parent =
        std::filesystem::weakly_canonical(output_parent, ec);
    if (ec || !std::filesystem::is_directory(normalized_parent, ec)) {
        return make_error("output directory does not exist");
    }
    const std::filesystem::path target = normalized_parent / output_path.filename();
    if (target == normalized_input) {
        // The model retains immutable original pages from path_ for undo/redo.
        return make_error("refusing to replace the currently loaded input file");
    }

    ec.clear();
    const bool exists = std::filesystem::exists(target, ec);
    if (ec) {
        return make_error("failed to query destination");
    }
    if (exists) {
        if (std::filesystem::equivalent(normalized_input, target, ec) && !ec) {
            return make_error("destination refers to the currently loaded input file");
        }
        if (ec) {
            return make_error("failed to compare input and destination");
        }
        if (!overwrite) {
            return make_error("output file already exists");
        }
    }

    // Create an exclusive staging directory on the destination filesystem.
    // Even a name collision cannot let a partial save truncate another file.
    std::random_device entropy;
    std::mt19937_64 random(entropy());
    std::filesystem::path staging_dir;
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        staging_dir = normalized_parent /
            (".peelf-staging-" + std::to_string(random()) + "-" + std::to_string(attempt));
        ec.clear();
        if (std::filesystem::create_directory(staging_dir, ec)) {
            break;
        }
        if (ec) {
            return make_error("cannot create staging directory");
        }
        staging_dir.clear();
    }
    if (staging_dir.empty()) {
        return make_error("could not allocate a unique staging directory");
    }

    struct RemoveStagingDirectory {
        std::filesystem::path directory;
        ~RemoveStagingDirectory() {
            std::error_code ignored;
            std::filesystem::remove_all(directory, ignored);
        }
    } cleanup{staging_dir};

    const std::filesystem::path staged_file = staging_dir / "patched-image.tmp";
    {
        std::ofstream output(staged_file, std::ios::binary | std::ios::trunc);
        if (!output) {
            return make_error("failed to open staged output");
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
                return make_error("failed to write complete staged output");
            }
            offset += chunk_size;
        }
        output.flush();
        if (!output) {
            return make_error("failed to flush staged output");
        }
        output.close();
        if (!output) {
            return make_error("failed to close staged output");
        }
    }

    ec.clear();
    if (std::filesystem::file_size(staged_file, ec) != size_ || ec) {
        return make_error("staged output length does not match input length");
    }

#ifndef _WIN32
    // Preserve ordinary executable/read permissions, excluding suid/sgid bits.
    ec.clear();
    const auto input_status = std::filesystem::status(normalized_input, ec);
    if (!ec) {
        constexpr auto ordinary_permissions =
            std::filesystem::perms::owner_all |
            std::filesystem::perms::group_all |
            std::filesystem::perms::others_all;
        std::filesystem::permissions(
            staged_file, input_status.permissions() & ordinary_permissions,
            std::filesystem::perm_options::replace, ec);
        if (ec) {
            return make_error("failed to copy output file permissions");
        }
    }
#endif

    // Publish only after the staged bytes have been completely written.
    // The non-overwrite path is no-clobber even if another process races to
    // create the destination while the new file is being prepared.
#ifdef _WIN32
    const DWORD flags = MOVEFILE_WRITE_THROUGH |
                        (overwrite ? MOVEFILE_REPLACE_EXISTING : DWORD{0});
    if (!MoveFileExW(staged_file.c_str(), target.c_str(), flags)) {
        return make_error("failed to publish staged output (destination may exist)");
    }
#else
    ec.clear();
    if (overwrite) {
        // POSIX rename replaces an existing regular file atomically.
        std::filesystem::rename(staged_file, target, ec);
    } else {
        // Hard-link publication is an atomic no-clobber operation.
        std::filesystem::create_hard_link(staged_file, target, ec);
    }
    if (ec) {
        return make_error("failed to publish staged output (destination may exist)");
    }
#endif
    return {};
}

} // namespace peelf
