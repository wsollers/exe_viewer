#include "panel_helpers.hpp"
#include "ui_panels_diff.hpp"
#include "ui_panels_capabilities.hpp"

#include "logger.hpp"

#include <imgui.h>

#include <algorithm>
#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <format>
#include <fstream>
#include <span>

namespace viewer {

namespace {

[[nodiscard]] bool contains_icase(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.empty()) return true;
    if (haystack.size() < needle.size()) return false;
    auto it = std::search(
        haystack.begin(),
        haystack.end(),
        needle.begin(),
        needle.end(),
        [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        });
    return it != haystack.end();
}

[[nodiscard]] ImVec4 color_for_diff_status(peelf::DiffChangeKind k) noexcept {
    switch (k) {
        case peelf::DiffChangeKind::Unchanged: return ImVec4(0.60f, 0.72f, 0.64f, 1.0f);
        case peelf::DiffChangeKind::Modified:  return ImVec4(0.98f, 0.78f, 0.28f, 1.0f);
        case peelf::DiffChangeKind::Added:     return ImVec4(0.35f, 0.92f, 0.55f, 1.0f);
        case peelf::DiffChangeKind::Removed:   return ImVec4(0.96f, 0.42f, 0.42f, 1.0f);
    }
    return ImVec4(0.8f, 0.8f, 0.8f, 1.0f);
}

[[nodiscard]] ImVec4 color_for_func_status(peelf::FunctionMatchKind k) noexcept {
    switch (k) {
        case peelf::FunctionMatchKind::Identical:          return ImVec4(0.58f, 0.75f, 0.62f, 1.0f);
        case peelf::FunctionMatchKind::IdenticalRelocated: return ImVec4(0.45f, 0.82f, 0.96f, 1.0f);
        case peelf::FunctionMatchKind::Modified:           return ImVec4(0.98f, 0.78f, 0.28f, 1.0f);
        case peelf::FunctionMatchKind::Added:              return ImVec4(0.35f, 0.92f, 0.55f, 1.0f);
        case peelf::FunctionMatchKind::Removed:            return ImVec4(0.96f, 0.42f, 0.42f, 1.0f);
    }
    return ImVec4(0.8f, 0.8f, 0.8f, 1.0f);
}

[[nodiscard]] ImVec4 color_for_hunk_class(peelf::ByteHunkClassification c) noexcept {
    switch (c) {
        case peelf::ByteHunkClassification::InlineCodeHook:
        case peelf::ByteHunkClassification::IatGotPointerHook:
            return ImVec4(0.98f, 0.34f, 0.36f, 1.0f);
        case peelf::ByteHunkClassification::CodeChange:
        case peelf::ByteHunkClassification::ReadOnlyDataModified:
            return ImVec4(0.98f, 0.76f, 0.28f, 1.0f);
        case peelf::ByteHunkClassification::RelocationOnly:
        case peelf::ByteHunkClassification::NormalizedLoaderSlot:
            return ImVec4(0.45f, 0.82f, 0.96f, 1.0f);
        case peelf::ByteHunkClassification::HeaderChange:
        case peelf::ByteHunkClassification::DataChange:
        case peelf::ByteHunkClassification::WritableRuntimeData:
            return ImVec4(0.80f, 0.76f, 0.58f, 1.0f);
    }
    return ImVec4(0.8f, 0.8f, 0.8f, 1.0f);
}

[[nodiscard]] std::string hex_preview_short(std::span<const std::uint8_t> bytes, std::size_t max_n = 10u) {
    std::string out;
    const std::size_t take = std::min(bytes.size(), max_n);
    for (std::size_t i = 0; i < take; ++i) {
        if (i > 0u) out.push_back(' ');
        out += std::format("{:02X}", bytes[i]);
    }
    if (bytes.size() > take) {
        out += " ...";
    }
    return out;
}

} // namespace

BinaryDiffPanel::BinaryDiffPanel(BinaryModel& model,
                                 ViewerSelection& selection,
                                 NavigateCallback on_navigate,
                                 BrowseFileCallback on_browse_file)
    : UiPanel("Binary Diff")
    , model_(model)
    , on_navigate_(std::move(on_navigate))
    , on_browse_file_(std::move(on_browse_file)) {
    (void)selection;
}

void BinaryDiffPanel::invalidate() noexcept {
    differ_.cancel();
    differ_.wait_for_idle();
    const bool had_report = static_report_.has_value() || live_report_.has_value();
    mode_ = ActiveDiffMode::None;
    static_report_.reset();
    live_report_.reset();
    if (had_report) {
        ++diff_revision_;
    }
    captured_revision_token_.reset();
    lhs_bytes_.clear();
    rhs_bytes_.clear();
    lhs_owned_image_.reset();
    rhs_owned_image_.reset();
    sbs_lhs_va_ = 0;
    sbs_rhs_va_ = 0;
    sbs_lhs_file_off_.reset();
    sbs_rhs_file_off_.reset();
    sbs_lhs_slice_.clear();
    sbs_rhs_slice_.clear();
    sbs_rhs_valid_.clear();
    sbs_lhs_insns_.clear();
    sbs_rhs_insns_.clear();
    status_message_.clear();
}

peelf::Result<void> BinaryDiffPanel::compare_with_file(const std::filesystem::path& comparison_path) {
    if (!model_.has_file() || model_.image() == nullptr) {
        return peelf::make_error("Load a primary binary or attach to a process before comparing");
    }
    if (comparison_path.empty() || !std::filesystem::exists(comparison_path)) {
        const std::string msg = std::format("Comparison path '{}' does not exist", comparison_path.string());
        status_message_ = msg;
        return peelf::make_error(msg);
    }

    // Snapshot primary effective bytes (including staged static patches if any)
    std::vector<std::uint8_t> primary_buf;
    if (!model_.is_live_process() && !model_.changed_intervals().empty()) {
        if (auto eff = model_.read_effective_bytes(0u, model_.bytes().size()); eff.has_value()) {
            primary_buf = std::move(*eff);
        }
    }
    if (primary_buf.empty()) {
        const auto span = model_.analysis_image_bytes();
        primary_buf.assign(span.begin(), span.end());
    }
    if (primary_buf.empty()) {
        return peelf::make_error("Primary binary has no readable image bytes");
    }

    peelf::BinaryDiffOptions opts;
    opts.lhs_label = std::filesystem::path(model_.file_info().path).filename().string();
    if (opts.lhs_label.empty()) opts.lhs_label = "Primary";
    opts.rhs_label = comparison_path.filename().string();
    if (model_.image()->is_universal_slice()) {
        opts.lhs_slice_index = model_.image()->container_slice_index();
    }

    const std::string path_str = comparison_path.string();
    std::snprintf(comparison_path_buf_.data(), comparison_path_buf_.size(), "%s", path_str.c_str());

    status_message_ = std::format("Comparing '{}' vs '{}' in background...", opts.lhs_label, opts.rhs_label);
    differ_.start_file_diff(
        model_.active_revision_token(),
        std::move(primary_buf),
        comparison_path,
        std::move(opts));
    set_visible(true);
    return {};
}

peelf::Result<void> BinaryDiffPanel::compare_active_live_module_vs_disk() {
    auto session_shared = model_.shared_process_session();
    if (!model_.is_live_process() || session_shared == nullptr) {
        return peelf::make_error("Attach to a live process first to run Disk-vs-RAM integrity comparison");
    }

    const peelf::ModuleInfo* active_mod = model_.active_module();
    peelf::ModuleInfo fallback_mod{};
    if (active_mod == nullptr && !model_.process_modules().empty()) {
        active_mod = &model_.process_modules().front();
    }
    if (active_mod == nullptr) {
        return peelf::make_error("No active loaded module in the attached process");
    }
    fallback_mod = *active_mod;

    std::filesystem::path disk_path = fallback_mod.path;
    if ((disk_path.empty() || !std::filesystem::exists(disk_path)) &&
        model_.resolved_executable_path().has_value()) {
        disk_path = *model_.resolved_executable_path();
    }
    if (disk_path.empty() || !std::filesystem::exists(disk_path)) {
        const std::string msg =
            std::format("Backing on-disk module '{}' is not accessible on filesystem", fallback_mod.path.string());
        status_message_ = msg;
        return peelf::make_error(msg);
    }

    peelf::LiveIntegrityDiffOptions opts;
    opts.include_writable_data_hunks = include_writable_live_data_;

    status_message_ = std::format(
        "Comparing live module '{}' (0x{:X}) against '{}' in background...",
        fallback_mod.name,
        fallback_mod.base_address,
        disk_path.filename().string());
    differ_.start_live_integrity_diff(
        model_.active_revision_token(),
        std::move(disk_path),
        std::move(session_shared),
        fallback_mod,
        std::move(opts));
    set_visible(true);
    return {};
}

void BinaryDiffPanel::poll_async_completion() {
    auto finished = differ_.poll_completed(model_.active_revision_token());
    if (!finished.has_value()) {
        return;
    }

    if (finished->status == AsyncDiffStatus::Cancelled) {
        status_message_ = "Binary diff cancelled.";
        return;
    }
    if (finished->status == AsyncDiffStatus::StaleDiscarded) {
        status_message_ = finished->error_message;
        return;
    }
    if (finished->status != AsyncDiffStatus::Succeeded) {
        status_message_ = finished->error_message;
        Log().error("Binary Diff: {}", finished->error_message);
        return;
    }

    captured_revision_token_ = model_.active_revision_token();

    if (finished->kind == AsyncDiffKind::TwoBinaries && finished->static_report.has_value()) {
        lhs_bytes_ = std::move(finished->lhs_bytes);
        lhs_owned_image_ = std::move(finished->lhs_image);
        rhs_bytes_ = std::move(finished->rhs_bytes);
        rhs_owned_image_ = std::move(finished->rhs_image);

        live_report_.reset();
        static_report_ = std::move(finished->static_report);
        ++diff_revision_;
        mode_ = ActiveDiffMode::TwoBinaries;
        selected_hunk_index_ = 0;

        if (lhs_owned_image_ != nullptr) {
            if (const auto arch = to_disassembler_architecture(lhs_owned_image_->architecture())) {
                (void)lhs_disasm_.init(*arch, to_disassembler_endianness(lhs_owned_image_->endianness()));
            }
        }
        if (rhs_owned_image_ != nullptr) {
            if (const auto arch = to_disassembler_architecture(rhs_owned_image_->architecture())) {
                (void)rhs_disasm_.init(*arch, to_disassembler_endianness(rhs_owned_image_->endianness()));
            }
        }

        if (!static_report_->byte_hunks.empty()) {
            const auto& h0 = static_report_->byte_hunks.front();
            focus_pair_cursor(h0.lhs_va, h0.rhs_va, h0.lhs_file_offset, h0.rhs_file_offset, 256u, false);
        } else if (lhs_owned_image_ != nullptr && rhs_owned_image_ != nullptr) {
            focus_pair_cursor(lhs_owned_image_->entry_point(),
                              rhs_owned_image_->entry_point(),
                              lhs_owned_image_->virtual_address_to_file_offset(lhs_owned_image_->entry_point()),
                              rhs_owned_image_->virtual_address_to_file_offset(rhs_owned_image_->entry_point()),
                              256u,
                              false);
        }

        status_message_ = std::format(
            "Compared '{}' vs '{}': {} modified section(s), {} changed byte(s), {} modified / {} relocated function(s)",
            finished->lhs_label,
            finished->rhs_label,
            static_report_->sections_modified,
            static_report_->total_changed_bytes,
            static_report_->functions_modified,
            static_report_->functions_relocated);
    } else if (finished->kind == AsyncDiffKind::DiskVsLiveRam && finished->live_report.has_value()) {
        lhs_bytes_ = std::move(finished->lhs_bytes);
        lhs_owned_image_ = std::move(finished->lhs_image);
        rhs_bytes_.clear();
        rhs_owned_image_.reset();

        static_report_.reset();
        live_report_ = std::move(finished->live_report);
        ++diff_revision_;
        mode_ = ActiveDiffMode::DiskVsLiveRam;
        selected_hunk_index_ = 0;

        if (lhs_owned_image_ != nullptr) {
            if (const auto arch = to_disassembler_architecture(lhs_owned_image_->architecture())) {
                (void)lhs_disasm_.init(*arch, to_disassembler_endianness(lhs_owned_image_->endianness()));
                (void)rhs_disasm_.init(*arch, to_disassembler_endianness(lhs_owned_image_->endianness()));
            }
        }

        if (!live_report_->findings.empty()) {
            const auto& h0 = live_report_->findings.front();
            focus_pair_cursor(h0.lhs_va, h0.rhs_va, h0.lhs_file_offset, std::nullopt, 256u, false);
        } else if (lhs_owned_image_ != nullptr) {
            const std::uint64_t entry_rva =
                lhs_owned_image_->entry_point() >= lhs_owned_image_->image_base()
                    ? (lhs_owned_image_->entry_point() - lhs_owned_image_->image_base())
                    : 0u;
            focus_pair_cursor(
                lhs_owned_image_->image_base() + entry_rva,
                finished->live_module.base_address + entry_rva,
                lhs_owned_image_->virtual_address_to_file_offset(lhs_owned_image_->image_base() + entry_rva),
                std::nullopt,
                256u,
                false);
        }

        status_message_ = live_report_->status.detail;
    }
}

void BinaryDiffPanel::focus_pair_cursor(std::optional<std::uint64_t> lhs_va,
                                        std::optional<std::uint64_t> rhs_va,
                                        std::optional<std::uint64_t> lhs_file_off,
                                        std::optional<std::uint64_t> rhs_file_off,
                                        std::size_t window_hint,
                                        bool also_jump_main_view) {
    sbs_window_bytes_ = std::clamp<std::size_t>(window_hint, 64u, 2048u);
    sbs_lhs_va_ = lhs_va.value_or(0u);
    sbs_rhs_va_ = rhs_va.value_or(0u);
    sbs_lhs_file_off_ = lhs_file_off;
    sbs_rhs_file_off_ = rhs_file_off;

    if (!sbs_lhs_file_off_.has_value() && lhs_owned_image_ != nullptr && sbs_lhs_va_ != 0u) {
        sbs_lhs_file_off_ = lhs_owned_image_->virtual_address_to_file_offset(sbs_lhs_va_);
    }
    if (!sbs_rhs_file_off_.has_value() && rhs_owned_image_ != nullptr && sbs_rhs_va_ != 0u) {
        sbs_rhs_file_off_ = rhs_owned_image_->virtual_address_to_file_offset(sbs_rhs_va_);
    }

    refresh_side_by_side_slices();

    if (also_jump_main_view && on_navigate_) {
        const std::uint64_t target_va = model_.is_live_process() ? sbs_rhs_va_ : sbs_lhs_va_;
        if (target_va != 0u) {
            on_navigate_(target_va, PreferredView::Disassembly);
        }
    }
}

void BinaryDiffPanel::refresh_side_by_side_slices() {
    sbs_lhs_slice_.clear();
    sbs_rhs_slice_.clear();
    sbs_rhs_valid_.clear();
    sbs_lhs_insns_.clear();
    sbs_rhs_insns_.clear();

    if (sbs_lhs_file_off_.has_value() && *sbs_lhs_file_off_ < lhs_bytes_.size()) {
        const std::size_t avail = lhs_bytes_.size() - static_cast<std::size_t>(*sbs_lhs_file_off_);
        const std::size_t take = std::min(avail, sbs_window_bytes_);
        sbs_lhs_slice_.assign(lhs_bytes_.begin() + static_cast<std::ptrdiff_t>(*sbs_lhs_file_off_),
                              lhs_bytes_.begin() + static_cast<std::ptrdiff_t>(*sbs_lhs_file_off_ + take));
    }

    if (mode_ == ActiveDiffMode::TwoBinaries) {
        if (sbs_rhs_file_off_.has_value() && *sbs_rhs_file_off_ < rhs_bytes_.size()) {
            const std::size_t avail = rhs_bytes_.size() - static_cast<std::size_t>(*sbs_rhs_file_off_);
            const std::size_t take = std::min(avail, sbs_window_bytes_);
            sbs_rhs_slice_.assign(rhs_bytes_.begin() + static_cast<std::ptrdiff_t>(*sbs_rhs_file_off_),
                                  rhs_bytes_.begin() + static_cast<std::ptrdiff_t>(*sbs_rhs_file_off_ + take));
        }
        sbs_rhs_valid_.assign(sbs_rhs_slice_.size(), 1u);
    } else if (mode_ == ActiveDiffMode::DiskVsLiveRam &&
               model_.is_live_process() && model_.process_session() != nullptr && sbs_rhs_va_ != 0u) {
        const auto samp = peelf::read_memory_tolerant(
            *model_.process_session(), model_.memory_regions(), sbs_rhs_va_, sbs_window_bytes_);
        sbs_rhs_slice_ = samp.bytes;
        sbs_rhs_valid_ = samp.valid;
        if (sbs_rhs_valid_.size() < sbs_rhs_slice_.size()) {
            sbs_rhs_valid_.resize(sbs_rhs_slice_.size(), 0u);
        }
    }

    if (!sbs_lhs_slice_.empty() && lhs_disasm_.is_initialized()) {
        sbs_lhs_insns_ = lhs_disasm_.disassemble(
            sbs_lhs_slice_.data(), sbs_lhs_slice_.size(), sbs_lhs_va_);
    }
    std::size_t readable_rhs_len = 0u;
    while (readable_rhs_len < sbs_rhs_slice_.size() &&
           (readable_rhs_len >= sbs_rhs_valid_.size() || sbs_rhs_valid_[readable_rhs_len] != 0u)) {
        ++readable_rhs_len;
    }
    if (readable_rhs_len > 0u && rhs_disasm_.is_initialized()) {
        sbs_rhs_insns_ = rhs_disasm_.disassemble(
            sbs_rhs_slice_.data(), readable_rhs_len, sbs_rhs_va_);
    }
}

void BinaryDiffPanel::draw_contents() {
    poll_async_completion();

    if (!model_.has_file()) {
        ImGui::TextDisabled("Open a primary binary or attach to a process to launch Binary Diff.");
        return;
    }

    const AsyncDiffProgress prog = differ_.progress();

    // Top Action Bar
    ImGui::BeginDisabled(prog.running);
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 22.0f);
    ImGui::InputTextWithHint("##DiffPath", "Path to comparison PE/ELF binary...",
                             comparison_path_buf_.data(), comparison_path_buf_.size());
    ImGui::SameLine();
    if (ImGui::Button("Browse...") && on_browse_file_) {
        on_browse_file_();
    }
    ImGui::SameLine();
    if (ImGui::Button("Compare File") && comparison_path_buf_[0] != '\0') {
        if (auto res = compare_with_file(utf8_to_filesystem_path(comparison_path_buf_.data())); !res) {
            Log().error("Binary Diff: {}", res.error().message);
        }
    }

    if (model_.is_live_process()) {
        ImGui::SameLine();
        if (ImGui::Button("Compare Active Live Module vs. Disk")) {
            if (auto res = compare_active_live_module_vs_disk(); !res) {
                Log().error("Live Module Integrity Diff: {}", res.error().message);
            }
        }
        ImGui::SameLine();
        if (ImGui::Checkbox("Include .data/.bss", &include_writable_live_data_) &&
            mode_ == ActiveDiffMode::DiskVsLiveRam) {
            (void)compare_active_live_module_vs_disk();
        }
    }
    ImGui::EndDisabled();

    if (prog.running) {
        const float fraction = prog.total_steps > 0u
            ? std::clamp(static_cast<float>(prog.completed_steps) / static_cast<float>(prog.total_steps), 0.0f, 1.0f)
            : 0.0f;
        ImGui::ProgressBar(fraction, ImVec2(ImGui::GetFontSize() * 16.0f, 0.0f));
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            differ_.cancel();
        }
        if (!prog.stage.empty()) {
            ImGui::SameLine();
            ImGui::TextUnformatted(prog.stage.c_str());
        }
    }

    // Filter controls
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 16.0f);
    ImGui::InputTextWithHint("##DiffFilter", "Filter functions, symbols, imports, sections...",
                             filter_buf_.data(), filter_buf_.size());
    ImGui::SameLine();
    ImGui::Checkbox("Changes / Hooks only", &changes_only_);

    if (!status_message_.empty()) {
        ImGui::TextWrapped("%s", status_message_.c_str());
    }

    const bool diff_is_stale =
        mode_ != ActiveDiffMode::None &&
        captured_revision_token_.has_value() &&
        *captured_revision_token_ != model_.active_revision_token();
    if (diff_is_stale) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.74f, 0.24f, 1.0f));
        ImGui::TextWrapped(
            "[STALE] Staged patches or target state changed since this diff ran — results may not match current bytes.");
        ImGui::PopStyleColor();
        ImGui::SameLine();
        ImGui::BeginDisabled(prog.running);
        if (ImGui::SmallButton("Re-run Diff")) {
            if (mode_ == ActiveDiffMode::TwoBinaries && comparison_path_buf_[0] != '\0') {
                (void)compare_with_file(utf8_to_filesystem_path(comparison_path_buf_.data()));
            } else if (mode_ == ActiveDiffMode::DiskVsLiveRam) {
                (void)compare_active_live_module_vs_disk();
            }
        }
        ImGui::EndDisabled();
    }

    ImGui::Separator();

    if (mode_ == ActiveDiffMode::None) {
        ImGui::TextDisabled(model_.is_live_process()
            ? "Click 'Compare Active Live Module vs. Disk' to detect inline code hooks & IAT/GOT hijacks, or choose a comparison binary."
            : "Select a second build of this PE/ELF binary above (or via File > Compare With Binary...) to inspect structural, function, and byte diffs.");
        return;
    }

    if (ImGui::BeginTabBar("BinaryDiffTabs")) {
        if (ImGui::BeginTabItem("Overview & Headers")) {
            draw_overview_tab();
            ImGui::EndTabItem();
        }
        if (mode_ == ActiveDiffMode::TwoBinaries && ImGui::BeginTabItem("Sections")) {
            draw_sections_tab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem(mode_ == ActiveDiffMode::DiskVsLiveRam ? "IAT / GOT Slots" : "Imports & Exports")) {
            draw_imports_exports_tab();
            ImGui::EndTabItem();
        }
        if (mode_ == ActiveDiffMode::TwoBinaries &&
            ImGui::BeginTabItem("Functions (Address-Shift Tolerant)")) {
            draw_functions_tab();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem(mode_ == ActiveDiffMode::DiskVsLiveRam ? "Integrity Findings / Hooks" : "Changed Byte Ranges")) {
            draw_hunks_tab();
            ImGui::EndTabItem();
        }
        const ImGuiTabItemFlags sbs_flags =
            switch_to_side_by_side_tab_ ? ImGuiTabItemFlags_SetSelected : ImGuiTabItemFlags_None;
        if (ImGui::BeginTabItem("Synchronized Side-by-Side Hex & Disasm", nullptr, sbs_flags)) {
            switch_to_side_by_side_tab_ = false;
            draw_side_by_side_tab();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}

void BinaryDiffPanel::draw_overview_tab() {
    if (mode_ == ActiveDiffMode::TwoBinaries && static_report_.has_value()) {
        const auto& r = *static_report_;
        ImGui::Text("Sections: +%zu / -%zu / ~%zu (=%zu)   |   Imports: +%zu / -%zu / ~%zu   |   Exports: +%zu / -%zu / ~%zu",
                    r.sections_added, r.sections_removed, r.sections_modified, r.sections_unchanged,
                    r.imports_added, r.imports_removed, r.imports_modified,
                    r.exports_added, r.exports_removed, r.exports_modified);
        ImGui::Text("Functions: %zu identical, %zu relocated (address-shift tolerant), %zu modified, +%zu added, -%zu removed",
                    r.functions_identical, r.functions_relocated, r.functions_modified,
                    r.functions_added, r.functions_removed);
        ImGui::Spacing();

        if (ImGui::BeginTable("DiffHeadersTable", 4,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
            ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed, 180.0f);
            ImGui::TableSetupColumn(r.header.lhs_label.c_str(), ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn(r.header.rhs_label.c_str(), ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 90.0f);
            ImGui::TableHeadersRow();

            for (const auto& f : r.header.fields) {
                if (changes_only_ && !f.changed) continue;
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(f.field_name.c_str());
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(f.lhs_value.c_str());
                ImGui::TableNextColumn();
                if (f.changed) {
                    ImGui::TextColored(ImVec4(0.98f, 0.78f, 0.28f, 1.0f), "%s", f.rhs_value.c_str());
                } else {
                    ImGui::TextUnformatted(f.rhs_value.c_str());
                }
                ImGui::TableNextColumn();
                ImGui::TextColored(
                    f.changed ? ImVec4(0.98f, 0.78f, 0.28f, 1.0f) : ImVec4(0.55f, 0.75f, 0.60f, 1.0f),
                    "%s", f.changed ? "Changed" : "Match");
            }
            ImGui::EndTable();
        }
    } else if (mode_ == ActiveDiffMode::DiskVsLiveRam && live_report_.has_value()) {
        const auto& lr = *live_report_;
        ImGui::TextDisabled("Sources:");
        ImGui::SameLine();
        ui_provenance::draw_provenance_badge(lr.disk_provenance, lr.disk_path);
        ImGui::SameLine();
        ImGui::TextDisabled("vs");
        ImGui::SameLine();
        ui_provenance::draw_provenance_badge(lr.live_provenance, lr.module_name);
        ImGui::SameLine();
        ui_provenance::draw_capture_stamp_badge("LiveDiff", lr.live_capture_stamp);
        ui_provenance::draw_backing_identity_banner(lr.backing_identity);
        ImGui::Text("Module: %s", lr.module_name.c_str());
        ImGui::Text("Backing Disk File: %s", lr.disk_path.c_str());
        ImGui::Text("Disk SHA-256: %s", lr.disk_sha256.c_str());
        ImGui::Text("Preferred Static Base: 0x%" PRIX64 "   |   Live Runtime Base: 0x%" PRIX64 "   |   ASLR Slide: %+" PRId64 " (0x%" PRIX64 ")",
                    lr.static_preferred_base,
                    lr.live_base_address,
                    lr.aslr_load_bias,
                    lr.live_base_address - lr.static_preferred_base);
        ImGui::Separator();
        ImGui::TextColored(lr.inline_code_hook_count > 0 ? ImVec4(0.98f, 0.34f, 0.36f, 1.0f)
                                                         : ImVec4(0.35f, 0.92f, 0.55f, 1.0f),
                           "Executable Inline Code Hooks (.text): %zu", lr.inline_code_hook_count);
        ImGui::TextColored(lr.iat_got_hook_count > 0 ? ImVec4(0.98f, 0.34f, 0.36f, 1.0f)
                                                     : ImVec4(0.35f, 0.92f, 0.55f, 1.0f),
                           "IAT / GOT Pointer Hooks: %zu", lr.iat_got_hook_count);
        ImGui::Text("Normalized Base Relocations: %zu   |   Clean Dynamic Loader Slots: %zu",
                    lr.normalized_relocation_count, lr.normalized_loader_slot_count);
        ImGui::Text("Read-Only Data Modifications: %zu   |   Writable (.data/.bss) Mutated Bytes: %" PRIu64,
                    lr.readonly_data_diff_count,
                    lr.writable_data_changed_bytes);
    }
}

void BinaryDiffPanel::draw_sections_tab() {
    if (!static_report_.has_value()) return;
    const std::string_view filt(filter_buf_.data());

    if (ImGui::BeginTable("DiffSectionsTable", 8,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Section", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 95.0f);
        ImGui::TableSetupColumn("Primary VA", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("Comp VA", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("Raw Size (L -> R)", ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableSetupColumn("Perms", ImGuiTableColumnFlags_WidthFixed, 95.0f);
        ImGui::TableSetupColumn("Changed Bytes", ImGuiTableColumnFlags_WidthFixed, 110.0f);
        ImGui::TableSetupColumn("SHA-256 (L / R)", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (std::size_t idx = 0; idx < static_report_->sections.size(); ++idx) {
            const auto& s = static_report_->sections[idx];
            if (changes_only_ && s.status == peelf::DiffChangeKind::Unchanged) continue;
            if (!contains_icase(s.name, filt)) continue;

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(idx));
            if (ImGui::Selectable(s.name.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                focus_pair_cursor(s.lhs_va, s.rhs_va, s.lhs_file_offset, s.rhs_file_offset, 256u, true);
                switch_to_side_by_side_tab_ = true;
            }
            ImGui::PopID();

            ImGui::TableNextColumn();
            ImGui::TextColored(color_for_diff_status(s.status), "%.*s",
                               static_cast<int>(peelf::to_string(s.status).size()),
                               peelf::to_string(s.status).data());
            ImGui::TableNextColumn();
            ImGui::Text("%s", s.lhs_va ? std::format("0x{:X}", *s.lhs_va).c_str() : "-");
            ImGui::TableNextColumn();
            ImGui::Text("%s", s.rhs_va ? std::format("0x{:X}", *s.rhs_va).c_str() : "-");
            ImGui::TableNextColumn();
            ImGui::Text("%" PRIu64 " -> %" PRIu64,
                        s.lhs_file_size,
                        s.rhs_file_size);
            ImGui::TableNextColumn();
            ImGui::Text("%s / %s",
                        s.lhs_permissions.empty() ? "-" : s.lhs_permissions.c_str(),
                        s.rhs_permissions.empty() ? "-" : s.rhs_permissions.c_str());
            ImGui::TableNextColumn();
            ImGui::Text("%" PRIu64, s.changed_byte_count);
            ImGui::TableNextColumn();
            const std::string lshort = s.lhs_sha256.size() >= 12 ? s.lhs_sha256.substr(0, 12) : "-";
            const std::string rshort = s.rhs_sha256.size() >= 12 ? s.rhs_sha256.substr(0, 12) : "-";
            ImGui::TextDisabled("%s / %s", lshort.c_str(), rshort.c_str());
        }
        ImGui::EndTable();
    }
}

void BinaryDiffPanel::draw_imports_exports_tab() {
    const std::string_view filt(filter_buf_.data());

    if (mode_ == ActiveDiffMode::DiskVsLiveRam && live_report_.has_value()) {
        if (ImGui::BeginTable("LiveSlotsTable", 6,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
            ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 75.0f);
            ImGui::TableSetupColumn("Library / Symbol", ImGuiTableColumnFlags_WidthFixed, 240.0f);
            ImGui::TableSetupColumn("Slot Live VA", ImGuiTableColumnFlags_WidthFixed, 135.0f);
            ImGui::TableSetupColumn("Live Target VA", ImGuiTableColumnFlags_WidthFixed, 135.0f);
            ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 90.0f);
            ImGui::TableSetupColumn("Resolution / Hook Detail", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            for (std::size_t idx = 0; idx < live_report_->loader_slots.size(); ++idx) {
                const auto& sl = live_report_->loader_slots[idx];
                if (changes_only_ && !sl.is_hooked) continue;
                if (!contains_icase(sl.symbol_name, filt) &&
                    !contains_icase(sl.library, filt) &&
                    !contains_icase(sl.target_module_name, filt)) continue;

                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(static_cast<int>(idx));
                if (ImGui::Selectable(sl.category.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                    if (on_navigate_) on_navigate_(sl.live_target_va != 0u ? sl.live_target_va : sl.live_slot_va,
                                                   PreferredView::Disassembly);
                }
                ImGui::PopID();

                ImGui::TableNextColumn();
                if (!sl.library.empty()) {
                    ImGui::Text("%s!%s", sl.library.c_str(), sl.symbol_name.c_str());
                } else {
                    ImGui::TextUnformatted(sl.symbol_name.c_str());
                }
                ImGui::TableNextColumn();
                ImGui::Text("0x%" PRIX64, sl.live_slot_va);
                ImGui::TableNextColumn();
                ImGui::Text("0x%" PRIX64, sl.live_target_va);
                ImGui::TableNextColumn();
                ImGui::TextColored(sl.is_hooked ? ImVec4(0.98f, 0.34f, 0.36f, 1.0f)
                                                : ImVec4(0.45f, 0.82f, 0.96f, 1.0f),
                                   "%s", sl.is_hooked ? "HOOKED" : "Resolved");
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(sl.detail.c_str());
            }
            ImGui::EndTable();
        }
        return;
    }

    if (!static_report_.has_value()) return;

    if (ImGui::CollapsingHeader("Imports Diff", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::BeginTable("DiffImportsTable", 5,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
                              ImVec2(0.0f, ImGui::GetFontSize() * 11.0f))) {
            ImGui::TableSetupColumn("Library", ImGuiTableColumnFlags_WidthFixed, 160.0f);
            ImGui::TableSetupColumn("Symbol / Ordinal", ImGuiTableColumnFlags_WidthFixed, 220.0f);
            ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 95.0f);
            ImGui::TableSetupColumn("IAT RVA (L -> R)", ImGuiTableColumnFlags_WidthFixed, 160.0f);
            ImGui::TableSetupColumn("Detail", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            for (const auto& imp : static_report_->imports) {
                if (changes_only_ && imp.status == peelf::DiffChangeKind::Unchanged) continue;
                if (!contains_icase(imp.library, filt) && !contains_icase(imp.symbol_or_ordinal, filt)) continue;
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(imp.library.c_str());
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(imp.symbol_or_ordinal.c_str());
                ImGui::TableNextColumn();
                ImGui::TextColored(color_for_diff_status(imp.status), "%.*s",
                                   static_cast<int>(peelf::to_string(imp.status).size()),
                                   peelf::to_string(imp.status).data());
                ImGui::TableNextColumn();
                ImGui::Text("%s -> %s",
                            imp.lhs_rva ? std::format("0x{:X}", *imp.lhs_rva).c_str() : "-",
                            imp.rhs_rva ? std::format("0x{:X}", *imp.rhs_rva).c_str() : "-");
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(imp.detail.c_str());
            }
            ImGui::EndTable();
        }
    }

    if (ImGui::CollapsingHeader("Exports Diff", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::BeginTable("DiffExportsTable", 5,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
                              ImVec2(0.0f, ImGui::GetFontSize() * 11.0f))) {
            ImGui::TableSetupColumn("Export", ImGuiTableColumnFlags_WidthFixed, 220.0f);
            ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 95.0f);
            ImGui::TableSetupColumn("Ordinal (L -> R)", ImGuiTableColumnFlags_WidthFixed, 120.0f);
            ImGui::TableSetupColumn("RVA (L -> R)", ImGuiTableColumnFlags_WidthFixed, 160.0f);
            ImGui::TableSetupColumn("Forwarder / Detail", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            for (const auto& exp : static_report_->exports) {
                if (changes_only_ && exp.status == peelf::DiffChangeKind::Unchanged) continue;
                if (!contains_icase(exp.name, filt)) continue;
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(exp.name.c_str());
                ImGui::TableNextColumn();
                ImGui::TextColored(color_for_diff_status(exp.status), "%.*s",
                                   static_cast<int>(peelf::to_string(exp.status).size()),
                                   peelf::to_string(exp.status).data());
                ImGui::TableNextColumn();
                ImGui::Text("%s -> %s",
                            exp.lhs_ordinal ? std::to_string(*exp.lhs_ordinal).c_str() : "-",
                            exp.rhs_ordinal ? std::to_string(*exp.rhs_ordinal).c_str() : "-");
                ImGui::TableNextColumn();
                ImGui::Text("%s -> %s",
                            exp.lhs_rva ? std::format("0x{:X}", *exp.lhs_rva).c_str() : "-",
                            exp.rhs_rva ? std::format("0x{:X}", *exp.rhs_rva).c_str() : "-");
                ImGui::TableNextColumn();
                if (!exp.rhs_forwarder.empty() || !exp.lhs_forwarder.empty()) {
                    ImGui::Text("%s -> %s",
                                exp.lhs_forwarder.empty() ? "-" : exp.lhs_forwarder.c_str(),
                                exp.rhs_forwarder.empty() ? "-" : exp.rhs_forwarder.c_str());
                } else {
                    ImGui::TextUnformatted(exp.detail.c_str());
                }
            }
            ImGui::EndTable();
        }
    }
}

void BinaryDiffPanel::draw_functions_tab() {
    if (!static_report_.has_value()) return;
    const std::string_view filt(filter_buf_.data());

    if (ImGui::BeginTable("DiffFunctionsTable", 7,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Function", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 135.0f);
        ImGui::TableSetupColumn("Basis", ImGuiTableColumnFlags_WidthFixed, 135.0f);
        ImGui::TableSetupColumn("Primary VA", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Comp VA", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Size (Delta)", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("Similarity", ImGuiTableColumnFlags_WidthFixed, 85.0f);
        ImGui::TableHeadersRow();

        for (std::size_t idx = 0; idx < static_report_->functions.size(); ++idx) {
            const auto& fn = static_report_->functions[idx];
            if (changes_only_ && fn.status == peelf::FunctionMatchKind::Identical) continue;
            if (!contains_icase(fn.display_name, filt) &&
                !contains_icase(fn.raw_lhs_name, filt) &&
                !contains_icase(fn.raw_rhs_name, filt)) continue;

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(idx));
            if (ImGui::Selectable(fn.display_name.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                const std::size_t win = static_cast<std::size_t>(
                    std::clamp<std::uint64_t>(std::max(fn.lhs_size, fn.rhs_size), 64u, 1024u));
                focus_pair_cursor(fn.lhs_va, fn.rhs_va, fn.lhs_file_offset, fn.rhs_file_offset, win, true);
                switch_to_side_by_side_tab_ = true;
            }
            ImGui::PopID();

            ImGui::TableNextColumn();
            const auto st_sv = peelf::to_string(fn.status);
            ImGui::TextColored(color_for_func_status(fn.status), "%.*s",
                               static_cast<int>(st_sv.size()), st_sv.data());
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", fn.match_basis.c_str());
            ImGui::TableNextColumn();
            ImGui::Text("%s", fn.lhs_va ? std::format("0x{:X}", *fn.lhs_va).c_str() : "-");
            ImGui::TableNextColumn();
            ImGui::Text("%s", fn.rhs_va ? std::format("0x{:X}", *fn.rhs_va).c_str() : "-");
            ImGui::TableNextColumn();
            ImGui::Text("%" PRIu64 " (%+" PRId64 ")",
                        fn.lhs_size != 0u ? fn.lhs_size : fn.rhs_size,
                        fn.size_delta);
            ImGui::TableNextColumn();
            ImGui::Text("%.1f%%", fn.similarity * 100.0);
        }
        ImGui::EndTable();
    }
}

void BinaryDiffPanel::draw_hunks_tab() {
    const std::vector<peelf::ByteDiffHunk>* hunks = nullptr;
    if (mode_ == ActiveDiffMode::TwoBinaries && static_report_.has_value()) {
        hunks = &static_report_->byte_hunks;
    } else if (mode_ == ActiveDiffMode::DiskVsLiveRam && live_report_.has_value()) {
        hunks = &live_report_->findings;
    }
    if (hunks == nullptr) return;

    const std::string_view filt(filter_buf_.data());

    if (ImGui::BeginTable("DiffHunksTable", 7,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Section", ImGuiTableColumnFlags_WidthFixed, 95.0f);
        ImGui::TableSetupColumn("Classification", ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableSetupColumn("Primary VA", ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn(mode_ == ActiveDiffMode::DiskVsLiveRam ? "Live VA" : "Comp VA",
                                ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 75.0f);
        ImGui::TableSetupColumn("Expected -> Actual Sample", ImGuiTableColumnFlags_WidthFixed, 250.0f);
        ImGui::TableSetupColumn("Symbol / Detail", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (std::size_t idx = 0; idx < hunks->size(); ++idx) {
            const auto& h = (*hunks)[idx];
            if (changes_only_ && h.classification == peelf::ByteHunkClassification::RelocationOnly) {
                continue;
            }
            if (!contains_icase(h.section_name, filt) &&
                !contains_icase(h.symbol_context, filt) &&
                !contains_icase(h.detail, filt)) {
                continue;
            }

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(idx));
            if (ImGui::Selectable(h.section_name.c_str(),
                                  selected_hunk_index_ == idx,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                selected_hunk_index_ = idx;
                focus_pair_cursor(h.lhs_va, h.rhs_va, h.lhs_file_offset, h.rhs_file_offset, 256u, true);
                switch_to_side_by_side_tab_ = true;
            }
            ImGui::PopID();

            ImGui::TableNextColumn();
            const auto cls_sv = peelf::to_string(h.classification);
            ImGui::TextColored(color_for_hunk_class(h.classification), "%.*s",
                               static_cast<int>(cls_sv.size()), cls_sv.data());
            ImGui::TableNextColumn();
            ImGui::Text("%s", h.lhs_va ? std::format("0x{:X}", *h.lhs_va).c_str() : "-");
            ImGui::TableNextColumn();
            ImGui::Text("%s", h.rhs_va ? std::format("0x{:X}", *h.rhs_va).c_str() : "-");
            ImGui::TableNextColumn();
            ImGui::Text("%" PRIu64, static_cast<std::uint64_t>(h.size));
            ImGui::TableNextColumn();
            ImGui::Text("%s -> %s",
                        hex_preview_short(h.lhs_sample, 6u).c_str(),
                        hex_preview_short(h.rhs_sample, 6u).c_str());
            ImGui::TableNextColumn();
            if (!h.symbol_context.empty() && !h.detail.empty()) {
                ImGui::Text("[%s] %s", h.symbol_context.c_str(), h.detail.c_str());
            } else if (!h.symbol_context.empty()) {
                ImGui::TextUnformatted(h.symbol_context.c_str());
            } else {
                ImGui::TextUnformatted(h.detail.c_str());
            }
        }
        ImGui::EndTable();
    }
}

void BinaryDiffPanel::draw_side_by_side_tab() {
    const std::vector<peelf::ByteDiffHunk>* hunks =
        (mode_ == ActiveDiffMode::TwoBinaries && static_report_) ? &static_report_->byte_hunks :
        (mode_ == ActiveDiffMode::DiskVsLiveRam && live_report_) ? &live_report_->findings : nullptr;

    ImGui::Checkbox("Lockstep Scroll", &lockstep_scroll_);
    ImGui::SameLine();
    if (hunks != nullptr && !hunks->empty()) {
        if (ImGui::Button("Prev Hunk")) {
            selected_hunk_index_ = (selected_hunk_index_ == 0u) ? (hunks->size() - 1u) : (selected_hunk_index_ - 1u);
            const auto& h = (*hunks)[selected_hunk_index_];
            focus_pair_cursor(h.lhs_va, h.rhs_va, h.lhs_file_offset, h.rhs_file_offset, sbs_window_bytes_, true);
        }
        ImGui::SameLine();
        if (ImGui::Button("Next Hunk")) {
            selected_hunk_index_ = (selected_hunk_index_ + 1u) % hunks->size();
            const auto& h = (*hunks)[selected_hunk_index_];
            focus_pair_cursor(h.lhs_va, h.rhs_va, h.lhs_file_offset, h.rhs_file_offset, sbs_window_bytes_, true);
        }
        ImGui::SameLine();
        ImGui::TextDisabled("Hunk %zu / %zu", selected_hunk_index_ + 1u, hunks->size());
        ImGui::SameLine();
    }
    if (ImGui::Button("Jump Main View Here") && on_navigate_) {
        const std::uint64_t target = model_.is_live_process() ? sbs_rhs_va_ : sbs_lhs_va_;
        if (target != 0u) on_navigate_(target, PreferredView::Disassembly);
    }
    ImGui::SameLine();
    ImGui::TextDisabled("Primary VA 0x%" PRIX64 "  <->  %s VA 0x%" PRIX64,
                        sbs_lhs_va_,
                        mode_ == ActiveDiffMode::DiskVsLiveRam ? "Live RAM" : "Comparison",
                        sbs_rhs_va_);

    // Synchronized Hex Rows (16 bytes per row)
    if (ImGui::CollapsingHeader("Synchronized Side-by-Side Hex", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::BeginTable("SideBySideHexTable", 4,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_ScrollY,
                              ImVec2(0.0f, ImGui::GetFontSize() * 10.5f))) {
            ImGui::TableSetupColumn("Primary VA", ImGuiTableColumnFlags_WidthFixed, 125.0f);
            ImGui::TableSetupColumn("Primary / Disk Bytes", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn(mode_ == ActiveDiffMode::DiskVsLiveRam ? "Live VA" : "Comp VA",
                                    ImGuiTableColumnFlags_WidthFixed, 125.0f);
            ImGui::TableSetupColumn(mode_ == ActiveDiffMode::DiskVsLiveRam ? "Live RAM Bytes" : "Comparison Bytes",
                                    ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            const std::size_t max_bytes = std::max(sbs_lhs_slice_.size(), sbs_rhs_slice_.size());
            for (std::size_t row_off = 0; row_off < max_bytes; row_off += 16u) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                if (row_off < sbs_lhs_slice_.size() || sbs_lhs_va_ != 0u || sbs_lhs_file_off_.has_value()) {
                    const std::uint64_t lhs_base =
                        sbs_lhs_va_ != 0u ? sbs_lhs_va_ : sbs_lhs_file_off_.value_or(0u);
                    ImGui::Text(sbs_lhs_va_ != 0u ? "0x%" PRIX64 : "off+0x%" PRIX64,
                                lhs_base + row_off);
                } else {
                    ImGui::TextDisabled("-");
                }

                ImGui::TableNextColumn();
                for (std::size_t b = 0; b < 16u && (row_off + b) < sbs_lhs_slice_.size(); ++b) {
                    if (b > 0u) ImGui::SameLine(0.0f, 4.0f);
                    const std::size_t cell = row_off + b;
                    const std::uint8_t lv = sbs_lhs_slice_[cell];
                    const bool has_r = cell < sbs_rhs_slice_.size();
                    const bool r_valid = has_r &&
                                         (cell >= sbs_rhs_valid_.size() || sbs_rhs_valid_[cell] != 0u);
                    const bool diff = !has_r || !r_valid || (sbs_rhs_slice_[cell] != lv);
                    if (diff) {
                        ImGui::TextColored(ImVec4(0.98f, 0.72f, 0.25f, 1.0f), "%02X", lv);
                    } else {
                        ImGui::TextDisabled("%02X", lv);
                    }
                }

                ImGui::TableNextColumn();
                if (row_off < sbs_rhs_slice_.size() || sbs_rhs_va_ != 0u || sbs_rhs_file_off_.has_value()) {
                    const std::uint64_t rhs_base =
                        sbs_rhs_va_ != 0u ? sbs_rhs_va_ : sbs_rhs_file_off_.value_or(0u);
                    ImGui::Text(sbs_rhs_va_ != 0u ? "0x%" PRIX64 : "off+0x%" PRIX64,
                                rhs_base + row_off);
                } else {
                    ImGui::TextDisabled("-");
                }

                ImGui::TableNextColumn();
                for (std::size_t b = 0; b < 16u && (row_off + b) < sbs_rhs_slice_.size(); ++b) {
                    if (b > 0u) ImGui::SameLine(0.0f, 4.0f);
                    const std::size_t cell = row_off + b;
                    const bool r_valid =
                        cell >= sbs_rhs_valid_.size() || sbs_rhs_valid_[cell] != 0u;
                    if (!r_valid) {
                        ImGui::TextColored(ImVec4(0.85f, 0.45f, 0.45f, 1.0f), "??");
                    } else {
                        const std::uint8_t rv = sbs_rhs_slice_[cell];
                        const bool diff = cell >= sbs_lhs_slice_.size() ||
                                          sbs_lhs_slice_[cell] != rv;
                        if (diff) {
                            ImGui::TextColored(ImVec4(0.98f, 0.38f, 0.38f, 1.0f), "%02X", rv);
                        } else {
                            ImGui::TextDisabled("%02X", rv);
                        }
                    }
                }
            }
            ImGui::EndTable();
        }
    }

    // Synchronized Side-by-Side Disassembly
    if (ImGui::CollapsingHeader("Synchronized Side-by-Side Disassembly", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::BeginTable("SideBySideDisasmTable", 4,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
            ImGui::TableSetupColumn("Primary VA", ImGuiTableColumnFlags_WidthFixed, 125.0f);
            ImGui::TableSetupColumn("Primary / Disk Instruction", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn(mode_ == ActiveDiffMode::DiskVsLiveRam ? "Live VA" : "Comp VA",
                                    ImGuiTableColumnFlags_WidthFixed, 125.0f);
            ImGui::TableSetupColumn(mode_ == ActiveDiffMode::DiskVsLiveRam ? "Live RAM Instruction" : "Comparison Instruction",
                                    ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            const std::size_t rows = std::max(sbs_lhs_insns_.size(), sbs_rhs_insns_.size());
            for (std::size_t i = 0; i < rows; ++i) {
                const Instruction* li = (i < sbs_lhs_insns_.size()) ? &sbs_lhs_insns_[i] : nullptr;
                const Instruction* ri = (i < sbs_rhs_insns_.size()) ? &sbs_rhs_insns_[i] : nullptr;
                const bool insn_diff = (li == nullptr || ri == nullptr) ||
                                       (li->mnemonic != ri->mnemonic) ||
                                       (li->bytes != ri->bytes);

                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                if (li != nullptr) {
                    ImGui::PushID(static_cast<int>(i));
                    if (ImGui::Selectable(std::format("0x{:X}", li->address).c_str())) {
                        if (on_navigate_) {
                            const std::uint64_t nav = (model_.is_live_process() && ri != nullptr)
                                                          ? ri->address
                                                          : li->address;
                            on_navigate_(nav, PreferredView::Disassembly);
                        }
                    }
                    ImGui::PopID();
                } else {
                    ImGui::TextDisabled("-");
                }

                ImGui::TableNextColumn();
                if (li != nullptr) {
                    const std::string text = li->to_string();
                    if (insn_diff) {
                        ImGui::TextColored(ImVec4(0.98f, 0.78f, 0.28f, 1.0f), "%s", text.c_str());
                    } else {
                        ImGui::TextUnformatted(text.c_str());
                    }
                }

                ImGui::TableNextColumn();
                if (ri != nullptr) {
                    ImGui::Text("0x%" PRIX64, ri->address);
                } else {
                    ImGui::TextDisabled("-");
                }

                ImGui::TableNextColumn();
                if (ri != nullptr) {
                    const std::string text = ri->to_string();
                    if (insn_diff) {
                        ImGui::TextColored(ImVec4(0.98f, 0.42f, 0.42f, 1.0f), "%s", text.c_str());
                    } else {
                        ImGui::TextUnformatted(text.c_str());
                    }
                }
            }
            ImGui::EndTable();
        }
    }
}

} // namespace viewer
