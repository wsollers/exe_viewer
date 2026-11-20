#include "panel_helpers.hpp"
#include "ui_panels.hpp"
#include "tools/shellcode_converter.hpp"

#include <peelf/assembler.hpp>
#include <peelf/patch_bundle.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <format>
#include <string>

#include <imgui.h>

namespace viewer {
namespace {

[[nodiscard]] std::string format_utc_timestamp_ms(std::int64_t timestamp_unix_ms) {
    if (timestamp_unix_ms <= 0) {
        return "-";
    }
    using namespace std::chrono;
    const sys_time<milliseconds> tp{milliseconds{timestamp_unix_ms}};
    const auto day_point = floor<days>(tp);
    const year_month_day ymd{day_point};
    const hh_mm_ss hms{floor<seconds>(tp - day_point)};
    return std::format("{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d} UTC",
                       static_cast<int>(ymd.year()),
                       static_cast<unsigned int>(ymd.month()),
                       static_cast<unsigned int>(ymd.day()),
                       static_cast<int>(hms.hours().count()),
                       static_cast<int>(hms.minutes().count()),
                       static_cast<int>(hms.seconds().count()));
}

[[nodiscard]] std::string format_bytes(const std::vector<std::uint8_t>& bytes, std::size_t max_visible = 8) {
    std::string output;
    const std::size_t count = std::min(max_visible, bytes.size());
    for (std::size_t i = 0; i < count; ++i) {
        std::array<char, 4> buffer{};
        std::snprintf(buffer.data(), buffer.size(), "%02X", bytes[i]);
        if (!output.empty()) {
            output += ' ';
        }
        output += buffer.data();
    }
    if (bytes.size() > max_visible) {
        output += " ...";
    }
    return output;
}

[[nodiscard]] std::string path_filename_utf8(const std::filesystem::path& path) {
    const auto u8_name = path.filename().u8string();
    return std::string(u8_name.begin(), u8_name.end());
}

} // namespace

PatchSetPanel::PatchSetPanel(BinaryModel& model, ViewerSelection& selection)
    : UiPanel("Patch Set"), model_(model), selection_(selection) {}

void PatchSetPanel::reset_for_new_target() {
    reset_preview();
    loaded_target_path_.clear();
    bundle_path_[0] = '\0';
    ips_path_[0] = '\0';
    bundle_name_[0] = '\0';
    bundle_desc_[0] = '\0';
    asm_input_[0] = '\0';
    patch_note_[0] = '\0';
    status_message_.clear();
}

void PatchSetPanel::refresh_live_assembly_preview() {
    live_asm_bytes_.clear();
    live_asm_disasm_.clear();
    live_asm_diag_.clear();

    if (!model_.image()) {
        last_asm_target_.reset();
        live_asm_diag_ = "Open a static PE/ELF binary to assemble instructions.";
        return;
    }

    const auto& image = *model_.image();
    std::uint64_t base_va = selection_.virtual_address.value_or(0);
    if (base_va == 0 && selection_.file_offset.has_value()) {
        base_va = image.file_offset_to_virtual_address(*selection_.file_offset)
                      .value_or(*selection_.file_offset);
    }
    const bool thumb = (thumb_ != nullptr && *thumb_);
    last_asm_target_ = ShellcodeTargetConfig{
        .architecture = image.architecture(),
        .endianness = image.endianness(),
        .is_64bit = image.is_64bit(),
        .thumb = thumb,
        .base_va = base_va,
        .assembly_mode = true,
    };

    if (asm_input_[0] == '\0') {
        live_asm_diag_ = std::format("Type {} assembly instructions for VA 0x{:X}.",
                                     peelf::to_string(image.architecture()),
                                     base_va);
        return;
    }

    auto res = peelf::assemble_instructions(
        image.architecture(),
        image.endianness(),
        image.is_64bit(),
        thumb,
        base_va,
        asm_input_);
    if (!res.has_value()) {
        live_asm_diag_ = res.error().message;
        return;
    }

    live_asm_bytes_ = std::move(res->bytes);
    live_asm_disasm_ = disassemble_patch_bytes(
        live_asm_bytes_, base_va, image.architecture(), image.endianness(), thumb);
    live_asm_diag_ = std::format(
        "{} encoded {} instruction(s) -> {} byte(s) at VA 0x{:X}: {}",
        res->provider_name,
        res->instruction_spans.size(),
        live_asm_bytes_.size(),
        base_va,
        format_bytes(live_asm_bytes_, 24));
}

void PatchSetPanel::refresh_imported_bundle_preview() {
    if (!imported_bundle_.has_value()) {
        imported_bundle_preview_.reset();
        return;
    }
    peelf::PatchBundleApplyOptions opts;
    opts.allow_hash_mismatch_if_original_bytes_match = bundle_allow_hash_mismatch_;
    auto prev = model_.preview_patch_bundle(*imported_bundle_, opts);
    if (!prev.has_value()) {
        imported_bundle_preview_.reset();
        bundle_status_ = prev.error().message;
        return;
    }
    bundle_status_ = prev->summary;
    imported_bundle_preview_ = std::move(*prev);
}

void PatchSetPanel::draw_contents() {
    const bool is_live = model_.is_live_process();

    if (is_live) {
        ImGui::TextColored(ImVec4(0.45f, 0.85f, 1.0f, 1.0f), "Read-Only Live Inspection");
        ImGui::Spacing();
        ImGui::TextWrapped(
            "Attached live processes are strictly read-only. Target process memory is never modified. "
            "Open a static PE/ELF binary from disk to assemble instructions, stage byte patches, "
            "apply .pepatch.json bundles, and export a patched copy.");
        return;
    }

    if (!status_message_.empty()) {
        ImGui::TextWrapped("%s", status_message_.c_str());
    }

    // Refresh default bundle path/name whenever the loaded static binary changes
    const std::string& current_target_path = model_.file_info().path;
    if (loaded_target_path_ != current_target_path) {
        loaded_target_path_ = current_target_path;
        imported_bundle_.reset();
        imported_bundle_preview_.reset();
        bundle_status_.clear();
        if (!current_target_path.empty()) {
            const std::string def_path = current_target_path + ".pepatch.json";
            const std::string def_ips = current_target_path + ".ips";
            std::snprintf(bundle_path_, sizeof(bundle_path_), "%s", def_path.c_str());
            std::snprintf(ips_path_, sizeof(ips_path_), "%s", def_ips.c_str());
            const std::string fname = path_filename_utf8(utf8_to_filesystem_path(current_target_path));
            std::snprintf(bundle_name_, sizeof(bundle_name_), "%s patches", fname.c_str());
        } else {
            bundle_path_[0] = '\0';
            ips_path_[0] = '\0';
            bundle_name_[0] = '\0';
        }
    } else if (bundle_path_[0] == '\0' && !current_target_path.empty()) {
        const std::string def_path = current_target_path + ".pepatch.json";
        std::snprintf(bundle_path_, sizeof(bundle_path_), "%s", def_path.c_str());
        if (ips_path_[0] == '\0') {
            const std::string def_ips = current_target_path + ".ips";
            std::snprintf(ips_path_, sizeof(ips_path_), "%s", def_ips.c_str());
        }
        if (bundle_name_[0] == '\0') {
            const std::string fname = path_filename_utf8(utf8_to_filesystem_path(current_target_path));
            std::snprintf(bundle_name_, sizeof(bundle_name_), "%s patches", fname.c_str());
        }
    }

    std::optional<std::uint64_t> target_offset = selection_.file_offset;
    if (!target_offset.has_value() && selection_.virtual_address.has_value()) {
        target_offset = model_.virtual_address_to_offset(*selection_.virtual_address);
    }
    const std::optional<std::uint64_t> target_va =
        target_offset.has_value() ? model_.offset_to_virtual_address(*target_offset) : selection_.virtual_address;

    if (target_offset.has_value()) {
        if (target_va.has_value()) {
            ImGui::Text("Target: File Offset 0x%" PRIX64 "  |  VA 0x%" PRIX64,
                        *target_offset,
                        *target_va);
        } else {
            ImGui::Text("Target: File Offset 0x%" PRIX64 "  |  (unmapped file region)",
                        *target_offset);
        }
    } else {
        ImGui::TextDisabled("Select an instruction, symbol, or byte in Disassembly / Hex View to target a patch.");
    }

    if (ImGui::RadioButton("Hex Bytes", input_mode_ == 0)) {
        input_mode_ = 0;
        preview_.reset();
    }
    ImGui::SameLine();
    if (ImGui::RadioButton("Assemble at Selection / VA", input_mode_ == 1)) {
        input_mode_ = 1;
        preview_.reset();
        refresh_live_assembly_preview();
    }

    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##patch_note",
                             "Analyst note (optional, recorded with transaction & .pepatch.json)",
                             patch_note_,
                             sizeof(patch_note_));

    if (input_mode_ == 0) {
        ImGui::TextDisabled("Preview a fixed-size hexadecimal replacement at the selected file offset.");
        ImGui::SetNextItemWidth(-1);
        if (ImGui::InputTextWithHint("##patch_bytes", "Replacement bytes, e.g. 90 90",
                                     replacement_, sizeof(replacement_))) {
            preview_.reset();
        }
        if (ImGui::Button("Preview Replacement")) {
            auto parsed = parse_hex_shellcode(replacement_);
            if (!parsed.success || parsed.bytes.empty() || !target_offset.has_value() || !symbols_) {
                status_ = "Select file bytes and enter a valid hexadecimal replacement.";
                preview_.reset();
            } else {
                auto result = preview_patch(model_, *symbols_, *target_offset, parsed.bytes, thumb_ && *thumb_);
                if (result) {
                    preview_ = std::move(*result);
                    status_ = "Preview ready; source file remains unchanged until staged.";
                } else {
                    status_ = result.error().message;
                    preview_.reset();
                }
            }
        }
    } else {
        if (model_.image() != nullptr) {
            const auto& img = *model_.image();
            const bool thumb = (thumb_ != nullptr && *thumb_);
            const auto* provider = peelf::default_assembler_registry().select_provider(
                img.architecture(), img.endianness(), img.is_64bit(), thumb);
            if (provider != nullptr) {
                ImGui::TextColored(ImVec4(0.45f, 0.90f, 0.60f, 1.0f),
                                   "Assembler Provider: %s",
                                   std::string(provider->name()).c_str());
            } else {
                const auto st = peelf::default_assembler_registry().target_status(
                    img.architecture(), img.endianness(), img.is_64bit(), thumb);
                ImGui::TextColored(ImVec4(1.0f, 0.65f, 0.30f, 1.0f),
                                   "Assembler Unavailable: %s",
                                   st.detail.c_str());
            }

            const ShellcodeTargetConfig cur_target{
                .architecture = img.architecture(),
                .endianness = img.endianness(),
                .is_64bit = img.is_64bit(),
                .thumb = thumb,
                .base_va = target_va.value_or(target_offset.value_or(0)),
                .assembly_mode = true,
            };
            if (!last_asm_target_.has_value() || *last_asm_target_ != cur_target) {
                preview_.reset();
                refresh_live_assembly_preview();
            }
        }

        if (ImGui::Checkbox("Pad trailing overwritten instruction slack with NOPs", &pad_nops_to_boundary_)) {
            preview_.reset();
        }
        if (ImGui::InputTextMultiline("##asm_patch_input",
                                      asm_input_,
                                      sizeof(asm_input_),
                                      ImVec2(-1.0f, 92.0f),
                                      ImGuiInputTextFlags_AllowTabInput)) {
            preview_.reset();
            refresh_live_assembly_preview();
        }

        if (!live_asm_diag_.empty()) {
            const ImVec4 diag_color = live_asm_bytes_.empty()
                                          ? ImVec4(0.95f, 0.65f, 0.35f, 1.0f)
                                          : ImVec4(0.65f, 0.88f, 0.98f, 1.0f);
            ImGui::TextColored(diag_color, "%s", live_asm_diag_.c_str());
        }
        if (!live_asm_disasm_.empty()) {
            ImGui::TextDisabled("Live Capstone Round-Trip:");
            for (const Instruction& inst : live_asm_disasm_) {
                ImGui::BulletText("0x%" PRIX64 ": %s %s  [%s]",
                                  inst.address,
                                  inst.mnemonic.c_str(),
                                  inst.operands.c_str(),
                                  format_bytes(inst.bytes, 16).c_str());
            }
        }

        ImGui::BeginDisabled(live_asm_bytes_.empty() || !target_offset.has_value() || symbols_ == nullptr);
        if (ImGui::Button("Preview Assembly Patch")) {
            auto result = preview_assembly_patch(
                model_,
                *symbols_,
                *target_offset,
                asm_input_,
                thumb_ && *thumb_,
                pad_nops_to_boundary_);
            if (result.has_value()) {
                preview_ = std::move(*result);
                status_ = "Assembly patch preview ready; review instruction boundaries before staging.";
            } else {
                status_ = result.error().message;
                preview_.reset();
            }
        }
        ImGui::EndDisabled();
    }

    if (preview_) {
        ImGui::Spacing();
        ImGui::Text("Preview Offset: 0x%" PRIX64 " | %zu byte(s) | Original: [%s] -> Patched: [%s]",
                    preview_->offset,
                    preview_->replacement.size(),
                    format_bytes(preview_->original_bytes, 12).c_str(),
                    format_bytes(preview_->replacement, 12).c_str());
        ImGui::TextWrapped("%s", preview_->boundary.c_str());
        if (preview_->misaligns_instruction_boundary && !preview_->boundary_warning.empty()) {
            ImGui::TextColored(ImVec4(1.0f, 0.60f, 0.25f, 1.0f),
                               "Boundary Warning: %s",
                               preview_->boundary_warning.c_str());
        }

        if (ImGui::BeginTable("patch_comparison", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_Resizable)) {
            ImGui::TableSetupColumn("Before (current effective code)");
            ImGui::TableSetupColumn("After replacement");
            ImGui::TableHeadersRow();
            ImGui::TableNextRow();
            for (const auto* graph : {&preview_->before, &preview_->after}) {
                ImGui::TableNextColumn();
                ImGui::Text("%zu blocks/nodes | %zu flow edges", graph->nodes.size(), graph->edges.size());
                ImGui::BeginChild(graph == &preview_->before ? "before_code" : "after_code",
                                  ImVec2(0, 190),
                                  false,
                                  ImGuiWindowFlags_HorizontalScrollbar);
                for (const auto& node : graph->nodes) {
                    ImGui::TextDisabled("%s", node.label.c_str());
                    for (const auto& instruction : node.instructions) {
                        ImGui::Text("%" PRIX64 "  %s %s",
                                    instruction.address,
                                    instruction.mnemonic.c_str(),
                                    instruction.operands.c_str());
                    }
                }
                for (const auto& edge : graph->edges) {
                    ImGui::TextDisabled("%s -> %s (%s)",
                                        edge.from_node_id.c_str(),
                                        edge.to_node_id.c_str(),
                                        edge.label.c_str());
                }
                ImGui::EndChild();
            }
            ImGui::EndTable();
        }

        ImGui::BeginDisabled(preview_->revision != model_.edit_revision());
        if (ImGui::Button("Stage Patch")) {
            preview_->note = patch_note_;
            auto result = apply_preview(model_, *preview_);
            status_ = result ? "Patch staged into PagedBinaryImage. Undo is available." : result.error().message;
            if (result) {
                patch_note_[0] = '\0';
            }
            preview_.reset();
            if (result && on_patch_mutated_) {
                on_patch_mutated_();
            }
        }
        ImGui::EndDisabled();
        if (preview_ && preview_->revision != model_.edit_revision()) {
            ImGui::TextDisabled("Bytes changed; preview again before staging.");
        }
    }

    ImGui::Separator();
    const auto* editable = model_.editable_image();
    ImGui::BeginDisabled(!editable || !editable->can_undo());
    if (ImGui::Button("Undo")) {
        const auto result = model_.undo_patch();
        status_ = result ? "Patch undone." : result.error().message;
        if (result && on_patch_mutated_) {
            on_patch_mutated_();
        }
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!editable || !editable->can_redo());
    if (ImGui::Button("Redo")) {
        const auto result = model_.redo_patch();
        status_ = result ? "Patch redone." : result.error().message;
        if (result && on_patch_mutated_) {
            on_patch_mutated_();
        }
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::TextDisabled("Export patched binary via File > Save Patched As...");
    if (!status_.empty()) {
        ImGui::TextWrapped("%s", status_.c_str());
    }

    if (editable != nullptr) {
        const auto commit_history = editable->undo_history();
        if (!commit_history.empty() && ImGui::CollapsingHeader("Transaction History")) {
            if (ImGui::BeginTable("PatchTxHistoryTable",
                                  4,
                                  ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                      ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
                                  ImVec2(0.0f, 110.0f))) {
                ImGui::TableSetupColumn("Committed (UTC)", ImGuiTableColumnFlags_WidthFixed, 155.0f);
                ImGui::TableSetupColumn("Label", ImGuiTableColumnFlags_WidthStretch, 0.40f);
                ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 75.0f);
                ImGui::TableSetupColumn("Analyst Note", ImGuiTableColumnFlags_WidthStretch, 0.60f);
                ImGui::TableHeadersRow();

                for (auto it = commit_history.rbegin(); it != commit_history.rend(); ++it) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    const std::string ts = format_utc_timestamp_ms(it->timestamp_unix_ms);
                    ImGui::TextUnformatted(ts.c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(it->label.c_str());
                    ImGui::TableNextColumn();
                    ImGui::Text("%" PRIu64, it->total_bytes);
                    ImGui::TableNextColumn();
                    if (!it->note.empty()) {
                        ImGui::TextUnformatted(it->note.c_str());
                    } else {
                        ImGui::TextDisabled("-");
                    }
                }
                ImGui::EndTable();
            }
        }
    }

    const std::vector<peelf::PatchInterval> patches = model_.changed_intervals();

    // -----------------------------------------------------------------------
    // Reusable Patch Bundles (.pepatch.json) & IPS/IPS32 Export
    // -----------------------------------------------------------------------
    ImGui::Separator();
    if (ImGui::CollapsingHeader("Reusable Patch Bundles (.pepatch.json) & IPS Export", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputTextWithHint("##bundle_path", "Bundle path (.pepatch.json)",
                                 bundle_path_, sizeof(bundle_path_));
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputTextWithHint("##ips_path", "IPS / IPS32 patch path (.ips)",
                                 ips_path_, sizeof(ips_path_));
        ImGui::SetNextItemWidth(220.0f);
        ImGui::InputTextWithHint("##bundle_name", "Bundle name", bundle_name_, sizeof(bundle_name_));
        ImGui::SameLine();
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputTextWithHint("##bundle_desc", "Description (optional)", bundle_desc_, sizeof(bundle_desc_));

        ImGui::BeginDisabled(patches.empty() || bundle_path_[0] == '\0' || !model_.has_file());
        if (ImGui::Button("Export Patch Bundle...")) {
            auto exported = model_.export_patch_bundle(bundle_name_, bundle_desc_);
            if (!exported.has_value()) {
                bundle_status_ = exported.error().message;
            } else {
                const std::filesystem::path bundle_fs_path = utf8_to_filesystem_path(bundle_path_);
                auto saved = peelf::save_patch_bundle_file(*exported, bundle_fs_path);
                bundle_status_ = saved.has_value()
                                     ? std::format("Exported {} patch entry(ies) to '{}'.",
                                                   exported->entries.size(),
                                                   bundle_path_)
                                     : saved.error().message;
            }
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::BeginDisabled(patches.empty() || ips_path_[0] == '\0' || !model_.has_file());
        if (ImGui::Button("Export IPS...")) {
            const std::filesystem::path ips_fs_path = utf8_to_filesystem_path(ips_path_);
            auto saved = peelf::save_ips_patch_file(patches, ips_fs_path);
            bundle_status_ = saved.has_value()
                                 ? std::format("Exported {} patch range(s) as IPS/IPS32 to '{}'.",
                                               patches.size(),
                                               ips_path_)
                                 : saved.error().message;
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::BeginDisabled(bundle_path_[0] == '\0' || !model_.has_file());
        if (ImGui::Button("Import & Preview Patch Bundle...")) {
            const std::filesystem::path bundle_fs_path = utf8_to_filesystem_path(bundle_path_);
            auto loaded = peelf::load_patch_bundle_file(bundle_fs_path);
            if (!loaded.has_value()) {
                imported_bundle_.reset();
                imported_bundle_preview_.reset();
                bundle_status_ = loaded.error().message;
            } else {
                imported_bundle_ = std::move(*loaded);
                refresh_imported_bundle_preview();
            }
        }
        ImGui::EndDisabled();

        if (ImGui::Checkbox("Allow SHA-256 mismatch when all original byte spans match",
                            &bundle_allow_hash_mismatch_)) {
            refresh_imported_bundle_preview();
        }

        if (!bundle_status_.empty()) {
            const ImVec4 col = (imported_bundle_preview_.has_value() && !imported_bundle_preview_->can_apply)
                                   ? ImVec4(1.0f, 0.65f, 0.30f, 1.0f)
                                   : ImVec4(0.65f, 0.90f, 0.70f, 1.0f);
            ImGui::TextColored(col, "%s", bundle_status_.c_str());
        }

        if (imported_bundle_.has_value() && imported_bundle_preview_.has_value()) {
            const auto& bp = *imported_bundle_preview_;
            ImGui::TextDisabled("Bundle '%s' (%s / %s) | Clean: %zu | Conflicts: %zu",
                                imported_bundle_->name.c_str(),
                                std::string(peelf::to_string(imported_bundle_->target_format)).c_str(),
                                std::string(peelf::to_string(imported_bundle_->target_arch)).c_str(),
                                bp.clean_count,
                                bp.conflict_count);

            if (ImGui::BeginTable("BundlePreviewTable",
                                  5,
                                  ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                      ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
                                  ImVec2(0.0f, 140.0f))) {
                ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 95.0f);
                ImGui::TableSetupColumn("VA", ImGuiTableColumnFlags_WidthFixed, 105.0f);
                ImGui::TableSetupColumn("Label", ImGuiTableColumnFlags_WidthStretch, 0.35f);
                ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                ImGui::TableSetupColumn("Detail", ImGuiTableColumnFlags_WidthStretch, 0.65f);
                ImGui::TableHeadersRow();

                for (const peelf::PatchBundleEntryPreview& ep : bp.entry_previews) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::Text("0x%08" PRIX64, ep.offset);
                    ImGui::TableNextColumn();
                    if (ep.virtual_address.has_value()) {
                        ImGui::Text("0x%" PRIX64, *ep.virtual_address);
                    } else {
                        ImGui::TextDisabled("-");
                    }
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(ep.label.c_str());
                    ImGui::TableNextColumn();
                    const ImVec4 st_col = (ep.status == peelf::PatchEntryConflictKind::Clean)
                                              ? ImVec4(0.45f, 0.92f, 0.55f, 1.0f)
                                              : ImVec4(1.0f, 0.55f, 0.35f, 1.0f);
                    ImGui::TextColored(st_col, "%s", std::string(peelf::to_string(ep.status)).c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(ep.detail.c_str());
                }
                ImGui::EndTable();
            }

            ImGui::BeginDisabled(!bp.can_apply);
            if (ImGui::Button("Apply Patch Bundle Atomically")) {
                peelf::PatchBundleApplyOptions opts;
                opts.allow_hash_mismatch_if_original_bytes_match = bundle_allow_hash_mismatch_;
                auto applied = model_.apply_patch_bundle(*imported_bundle_, opts);
                if (applied.has_value()) {
                    bundle_status_ = std::format("Applied {} patch entry(ies) transactionally.",
                                                 imported_bundle_->entries.size());
                    imported_bundle_.reset();
                    imported_bundle_preview_.reset();
                    if (on_patch_mutated_) {
                        on_patch_mutated_();
                    }
                } else {
                    bundle_status_ = applied.error().message;
                }
            }
            ImGui::EndDisabled();
            ImGui::SameLine();
            if (ImGui::Button("Dismiss Bundle Preview")) {
                imported_bundle_.reset();
                imported_bundle_preview_.reset();
            }
        }
    }

    ImGui::Separator();
    if (patches.empty()) {
        ImGui::TextDisabled("No staged patches.");
        return;
    }

    ImGui::TextDisabled("%zu staged range%s", patches.size(), patches.size() == 1 ? "" : "s");
    ImGui::Separator();

    if (ImGui::BeginTable("PatchSetTable",
                          7,
                          ImGuiTableFlags_Borders |
                              ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable |
                              ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 105.0f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 65.0f);
        ImGui::TableSetupColumn("Original", ImGuiTableColumnFlags_WidthStretch, 0.35f);
        ImGui::TableSetupColumn("Patched", ImGuiTableColumnFlags_WidthStretch, 0.35f);
        ImGui::TableSetupColumn("Committed (UTC)", ImGuiTableColumnFlags_WidthFixed, 155.0f);
        ImGui::TableSetupColumn("Note", ImGuiTableColumnFlags_WidthStretch, 0.30f);
        ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableHeadersRow();

        for (std::size_t i = 0; i < patches.size(); ++i) {
            const peelf::PatchInterval& patch = patches[i];
            const ViewerSelection patch_selection =
                selection_from_patch_interval(patch, static_cast<std::uint64_t>(i));
            const bool selected = selection_.kind == SelectionKind::Patch &&
                                  selection_.object_index == static_cast<std::uint64_t>(i) &&
                                  selection_.file_offset == patch.offset;

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(i));
            std::array<char, 32> label{};
            std::snprintf(label.data(), label.size(), "0x%08" PRIX64, patch.offset);
            if (ImGui::Selectable(label.data(), selected, ImGuiSelectableFlags_SpanAllColumns)) {
                selection_ = patch_selection;
                if (on_patch_activated_) {
                    on_patch_activated_(patch_selection);
                }
            }
            ImGui::PopID();

            ImGui::TableNextColumn();
            ImGui::Text("%zu", patch.patched.size());

            ImGui::TableNextColumn();
            const std::string original = format_bytes(patch.original);
            ImGui::TextUnformatted(original.c_str());

            ImGui::TableNextColumn();
            const std::string patched = format_bytes(patch.patched);
            ImGui::TextUnformatted(patched.c_str());

            ImGui::TableNextColumn();
            const std::string ts = format_utc_timestamp_ms(patch.timestamp_unix_ms);
            ImGui::TextUnformatted(ts.c_str());

            ImGui::TableNextColumn();
            if (!patch.note.empty()) {
                ImGui::TextUnformatted(patch.note.c_str());
            } else {
                ImGui::TextDisabled("-");
            }

            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(i));
            if (ImGui::SmallButton("Revert")) {
                const auto result = model_.apply_patch_bytes(patch.offset, patch.original, "Revert patch range");
                status_ = result ? "Range restored; Undo can recover it." : result.error().message;
                if (result && on_patch_mutated_) {
                    on_patch_mutated_();
                }
            }
            ImGui::PopID();
        }

        ImGui::EndTable();
    }
}

} // namespace viewer
