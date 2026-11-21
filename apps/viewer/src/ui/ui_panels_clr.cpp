// SPDX-License-Identifier: BSD-2-Clause
#include "ui_panels_clr.hpp"

#include <imgui.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace viewer {
namespace {

[[nodiscard]] char ascii_lower_char(char c) noexcept {
    if (c >= 'A' && c <= 'Z') {
        return static_cast<char>(c - 'A' + 'a');
    }
    return c;
}

[[nodiscard]] bool icontains_ascii(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    if (needle.size() > haystack.size()) {
        return false;
    }
    const std::size_t limit = haystack.size() - needle.size();
    for (std::size_t i = 0; i <= limit; ++i) {
        bool match = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            if (ascii_lower_char(haystack[i + j]) != ascii_lower_char(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::string escape_single_line(std::string_view input, std::size_t max_chars = 256u) {
    std::string out;
    out.reserve(std::min(input.size(), max_chars));
    for (const char ch : input) {
        if (out.size() >= max_chars) {
            out += "...";
            break;
        }
        if (ch == '\n') {
            out += "\\n";
        } else if (ch == '\r') {
            out += "\\r";
        } else if (ch == '\t') {
            out += "\\t";
        } else if (static_cast<unsigned char>(ch) < 0x20u) {
            out += std::format("\\x{:02X}", static_cast<unsigned int>(static_cast<unsigned char>(ch)));
        } else {
            out.push_back(ch);
        }
    }
    return out;
}

void draw_kv_row(const char* key, std::string_view value) {
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::TextDisabled("%s", key);
    ImGui::TableSetColumnIndex(1);
    ImGui::TextUnformatted(value.data(), value.data() + value.size());
}

} // namespace

ClrMetadataPanel::ClrMetadataPanel(BinaryModel& model,
                                   ViewerSelection& selection,
                                   NavigateOffsetCallback on_navigate_offset)
    : UiPanel(".NET / CLR")
    , model_(model)
    , selection_(selection)
    , on_navigate_offset_(std::move(on_navigate_offset)) {}

void ClrMetadataPanel::sync_model_cache(const peelf::ClrMetadata& md) {
    const peelf::IBinaryImage* img = model_.image();
    if (img == cached_image_ptr_ &&
        md.metadata_rva == cached_metadata_rva_ &&
        md.metadata_size == cached_metadata_size_ &&
        md.methods.size() == cached_method_count_ &&
        md.type_defs.size() == cached_typedef_count_) {
        return;
    }

    cached_image_ptr_ = img;
    cached_metadata_rva_ = md.metadata_rva;
    cached_metadata_size_ = md.metadata_size;
    cached_method_count_ = md.methods.size();
    cached_typedef_count_ = md.type_defs.size();

    all_member_rows_.clear();
    filtered_member_indices_.clear();
    selected_method_index_.reset();
    cached_cil_body_.reset();
    cached_cil_error_.clear();
    highlighted_il_offset_.reset();
    types_filter_dirty_ = true;

    const std::size_t estimated_rows =
        md.type_defs.size() + md.fields.size() + md.methods.size();
    all_member_rows_.reserve(estimated_rows);

    for (std::size_t ti = 0; ti < md.type_defs.size(); ++ti) {
        const peelf::ClrTypeDef& td = md.type_defs[ti];
        const std::string full = td.full_name();
        std::string detail = td.visibility_summary;
        if (!td.kind_summary.empty()) {
            if (!detail.empty()) detail += " ";
            detail += td.kind_summary;
        }
        if (!td.extends_name.empty()) {
            detail += " : ";
            detail += td.extends_name;
        }
        all_member_rows_.push_back(MemberRow{
            .kind = MemberRowKind::TypeDef,
            .index = ti,
            .token = td.token,
            .rva = 0u,
            .display_name = full,
            .detail = detail,
            .search_key = std::format("0x{:08X} {} {}", td.token, full, detail),
        });

        const std::size_t field_start = static_cast<std::size_t>(td.field_start_index);
        const std::size_t field_end =
            std::min(md.fields.size(), field_start + static_cast<std::size_t>(td.field_count));
        for (std::size_t fi = field_start; fi < field_end; ++fi) {
            const peelf::ClrFieldDef& fd = md.fields[fi];
            const std::string detail_str = std::format("{} ({})", fd.type_signature, fd.flags_summary);
            all_member_rows_.push_back(MemberRow{
                .kind = MemberRowKind::Field,
                .index = fi,
                .token = fd.token,
                .rva = 0u,
                .display_name = std::format("  .field {}", fd.name),
                .detail = detail_str,
                .search_key = std::format("0x{:08X} {}::{} {}", fd.token, full, fd.name, detail_str),
            });
        }

        const std::size_t method_start = static_cast<std::size_t>(td.method_start_index);
        const std::size_t method_end =
            std::min(md.methods.size(), method_start + static_cast<std::size_t>(td.method_count));
        for (std::size_t mi = method_start; mi < method_end; ++mi) {
            const peelf::ClrMethodDef& m = md.methods[mi];
            all_member_rows_.push_back(MemberRow{
                .kind = MemberRowKind::Method,
                .index = mi,
                .token = m.token,
                .rva = m.rva,
                .display_name = std::format("  .method {}", m.name),
                .detail = m.signature_summary,
                .search_key = std::format(
                    "0x{:08X} {}::{} {} {}", m.token, full, m.name, m.signature_summary, m.flags_summary),
            });
        }
    }

    // Prefer EntryPointToken if it names a MethodDef with IL; otherwise pick the first IL method.
    std::optional<std::size_t> initial_method;
    if ((md.entry_point_token_or_rva >> 24u) == 0x06u) {
        const std::uint32_t ep_rid = md.entry_point_token_or_rva & 0x00FFFFFFu;
        if (ep_rid >= 1u && static_cast<std::size_t>(ep_rid - 1u) < md.methods.size() &&
            md.methods[static_cast<std::size_t>(ep_rid - 1u)].rva != 0u) {
            initial_method = static_cast<std::size_t>(ep_rid - 1u);
        }
    }
    if (!initial_method.has_value()) {
        for (std::size_t mi = 0; mi < md.methods.size(); ++mi) {
            if (md.methods[mi].rva != 0u) {
                initial_method = mi;
                break;
            }
        }
    }
    if (!initial_method.has_value() && !md.methods.empty()) {
        initial_method = 0u;
    }
    if (initial_method.has_value()) {
        select_method_index(*initial_method, md);
    }
}

void ClrMetadataPanel::rebuild_filtered_member_rows() {
    filtered_member_indices_.clear();
    const std::string_view query(types_filter_buf_);
    filtered_member_indices_.reserve(all_member_rows_.size());
    for (std::size_t i = 0; i < all_member_rows_.size(); ++i) {
        const MemberRow& row = all_member_rows_[i];
        if (methods_with_il_only_) {
            if (row.kind != MemberRowKind::Method || row.rva == 0u) {
                continue;
            }
        }
        if (!query.empty() && !icontains_ascii(row.search_key, query)) {
            continue;
        }
        filtered_member_indices_.push_back(i);
    }
    types_filter_dirty_ = false;
}

void ClrMetadataPanel::select_method_index(std::size_t method_index, const peelf::ClrMetadata& md) {
    selected_method_index_ = method_index;
    cached_cil_body_.reset();
    cached_cil_error_.clear();
    highlighted_il_offset_.reset();

    if (method_index >= md.methods.size()) {
        return;
    }
    const peelf::ClrMethodDef& method = md.methods[method_index];
    if (method.rva == 0u) {
        cached_cil_error_ = "Method has RVA 0 (abstract, runtime-provided, or P/Invoke native import).";
        return;
    }
    const peelf::IBinaryImage* img = model_.image();
    if (img == nullptr) {
        cached_cil_error_ = "Binary image handle is unavailable.";
        return;
    }

    const std::span<const std::uint8_t> base_bytes = model_.analysis_image_bytes();
    std::vector<std::uint8_t> patched_bytes;
    std::span<const std::uint8_t> effective_bytes = base_bytes;
    if (model_.edit_revision() != 0u && !base_bytes.empty()) {
        const std::uint64_t slice_off = img->container_slice_offset();
        if (auto eff = model_.read_effective_bytes(slice_off, base_bytes.size()); eff.has_value()) {
            patched_bytes = std::move(*eff);
            effective_bytes = patched_bytes;
        }
    }

    if (auto dis = peelf::disassemble_cil_method(*img, effective_bytes, md, method); dis.has_value()) {
        cached_cil_body_ = std::move(*dis);
    } else {
        cached_cil_error_ = dis.error().message;
    }
}

void ClrMetadataPanel::draw_contents() {
    if (!model_.has_file()) {
        ImGui::TextDisabled(
            "Open a PE executable or .NET assembly to inspect ECMA-335 metadata and CIL bytecode.");
        return;
    }

    const peelf::IBinaryImage* img = model_.image();
    if (img == nullptr || img->pe_clr_header() == nullptr) {
        ImGui::TextDisabled(
            "No IMAGE_COR20_HEADER (.NET / CLR runtime directory) is present in this binary.");
        return;
    }

    if (!model_.clr_metadata().has_value()) {
        const peelf::PeClrHeader& clr = *img->pe_clr_header();
        ImGui::TextColored(
            ImVec4(0.95f, 0.65f, 0.25f, 1.0f),
            "IMAGE_COR20_HEADER detected (Metadata RVA 0x%X, %u bytes), but BSJB metadata could not be decoded.",
            clr.metadata_rva,
            clr.metadata_size);
        if (!model_.clr_metadata_error().empty()) {
            ImGui::Spacing();
            ImGui::TextWrapped("Diagnostic: %s", model_.clr_metadata_error().c_str());
        }
        return;
    }

    const peelf::ClrMetadata& md = *model_.clr_metadata();
    sync_model_cache(md);

    if (ImGui::BeginTabBar("##ClrInspectorTabs")) {
        if (ImGui::BeginTabItem("Overview & Refs")) {
            render_overview_tab(md);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Types & CIL")) {
            render_types_and_cil_tab(md);
            ImGui::EndTabItem();
        }
        const std::string pinvoke_label = std::format("P/Invoke ({})###ClrPInvokeTab", md.pinvoke_entries.size());
        if (ImGui::BeginTabItem(pinvoke_label.c_str())) {
            render_pinvoke_tab(md);
            ImGui::EndTabItem();
        }
        const std::string us_label = std::format("User Strings (#US) ({})###ClrUsTab", md.user_strings.size());
        if (ImGui::BeginTabItem(us_label.c_str())) {
            render_user_strings_tab(md);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}

void ClrMetadataPanel::render_overview_tab(const peelf::ClrMetadata& md) {
    if (ImGui::BeginTable(
            "##ClrOverviewSummary",
            2,
            ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupColumn("Property", ImGuiTableColumnFlags_WidthFixed, 170.0f);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);

        const peelf::PeClrHeader* clr_hdr =
            model_.image() != nullptr ? model_.image()->pe_clr_header() : nullptr;
        draw_kv_row(
            "COR20 Header",
            clr_hdr != nullptr
                ? std::format(
                      "v{}.{} @ file +0x{:X} ({} bytes)",
                      md.cor20_major_runtime_version,
                      md.cor20_minor_runtime_version,
                      clr_hdr->file_offset,
                      clr_hdr->size)
                : std::format(
                      "v{}.{}",
                      md.cor20_major_runtime_version,
                      md.cor20_minor_runtime_version));
        draw_kv_row(
            "COMIMAGE Flags",
            std::format("0x{:08X} ({})", md.cor20_flags, md.cor20_flags_summary));
        draw_kv_row(
            "Metadata Root (BSJB)",
            std::format(
                "RVA 0x{:X} (file +0x{:X}, {} bytes) | Runtime {} | v{}.{} ({})",
                md.metadata_rva,
                md.metadata_file_offset,
                md.metadata_size,
                md.runtime_version,
                md.md_major_version,
                md.md_minor_version,
                md.compressed_tables ? "#~ compressed" : "#- uncompressed"));
        draw_kv_row("EntryPointToken", std::format("0x{:08X}", md.entry_point_token_or_rva));
        const std::string mod_name =
            (md.module.has_value() && !md.module->name.empty()) ? md.module->name : "<unnamed>";
        const std::string mod_mvid =
            (md.module.has_value() && !md.module->mvid_guid.empty()) ? md.module->mvid_guid : "<none>";
        draw_kv_row(
            "Module",
            std::format("{} (MVID: {})", mod_name, mod_mvid));
        if (md.assembly.has_value()) {
            const peelf::ClrAssemblyInfo& asm_info = *md.assembly;
            draw_kv_row(
                "Assembly",
                std::format(
                    "{}, Version={}, Culture={}, PublicKey={}",
                    asm_info.name,
                    asm_info.version_string(),
                    asm_info.culture.empty() ? "neutral" : asm_info.culture,
                    asm_info.public_key_hex.empty() ? "null" : asm_info.public_key_hex));
        } else {
            draw_kv_row("Assembly", "<no Assembly table row>");
        }
        draw_kv_row(
            "Table Counts",
            std::format(
                "TypeDef={} | TypeRef={} | MethodDef={} | Field={} | MemberRef={} | P/Invoke={} | #US={}",
                md.type_defs.size(),
                md.type_refs.size(),
                md.methods.size(),
                md.fields.size(),
                md.member_refs.size(),
                md.pinvoke_entries.size(),
                md.user_strings.size()));
        ImGui::EndTable();
    }

    if (!md.diagnostics.empty()) {
        ImGui::Spacing();
        ImGui::TextColored(
            ImVec4(0.95f, 0.72f, 0.25f, 1.0f),
            "Parser Diagnostics (%zu):",
            md.diagnostics.size());
        for (const std::string& diag : md.diagnostics) {
            ImGui::BulletText("%s", diag.c_str());
        }
    }

    ImGui::Spacing();
    if (ImGui::CollapsingHeader("Metadata Streams", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::BeginTable(
                "##ClrStreamsTable",
                3,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("Stream", ImGuiTableColumnFlags_WidthFixed, 120.0f);
            ImGui::TableSetupColumn("Rel Offset", ImGuiTableColumnFlags_WidthFixed, 110.0f);
            ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();
            for (const peelf::ClrStreamHeaderInfo& sh : md.streams) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::TextUnformatted(sh.name.c_str());
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("0x%X", sh.offset);
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%u bytes", sh.size);
            }
            ImGui::EndTable();
        }
    }

    const std::string asm_ref_hdr =
        std::format("Assembly References ({})###ClrAssemblyRefsHdr", md.assembly_refs.size());
    if (ImGui::CollapsingHeader(asm_ref_hdr.c_str(), ImGuiTreeNodeFlags_DefaultOpen)) {
        if (md.assembly_refs.empty()) {
            ImGui::TextDisabled("No AssemblyRef rows.");
        } else if (ImGui::BeginTable(
                       "##ClrAssemblyRefTable",
                       5,
                       ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
                           ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("Token", ImGuiTableColumnFlags_WidthFixed, 92.0f);
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 1.4f);
            ImGui::TableSetupColumn("Version", ImGuiTableColumnFlags_WidthFixed, 100.0f);
            ImGui::TableSetupColumn("Culture", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("PublicKeyOrToken", ImGuiTableColumnFlags_WidthStretch, 1.2f);
            ImGui::TableHeadersRow();
            for (const peelf::ClrAssemblyRef& ar : md.assembly_refs) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Text("0x%08X", ar.token);
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(ar.name.c_str());
                ImGui::TableSetColumnIndex(2);
                const std::string ver = ar.version_string();
                ImGui::TextUnformatted(ver.c_str());
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(ar.culture.empty() ? "neutral" : ar.culture.c_str());
                ImGui::TableSetColumnIndex(4);
                ImGui::TextUnformatted(
                    ar.public_key_or_token_hex.empty() ? "null" : ar.public_key_or_token_hex.c_str());
            }
            ImGui::EndTable();
        }
    }

    const std::string typeref_hdr =
        std::format("Type References ({})###ClrTypeRefsHdr", md.type_refs.size());
    if (ImGui::CollapsingHeader(typeref_hdr.c_str())) {
        if (md.type_refs.empty()) {
            ImGui::TextDisabled("No TypeRef rows.");
        } else if (ImGui::BeginTable(
                       "##ClrTypeRefTable",
                       4,
                       ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
                           ImGuiTableFlags_ScrollY,
                       ImVec2(0.0f, 200.0f))) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Token", ImGuiTableColumnFlags_WidthFixed, 92.0f);
            ImGui::TableSetupColumn("Namespace", ImGuiTableColumnFlags_WidthStretch, 1.1f);
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 1.2f);
            ImGui::TableSetupColumn("ResolutionScope", ImGuiTableColumnFlags_WidthStretch, 1.0f);
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(md.type_refs.size()));
            while (clipper.Step()) {
                for (int row_i = clipper.DisplayStart; row_i < clipper.DisplayEnd; ++row_i) {
                    const peelf::ClrTypeRef& tr = md.type_refs[static_cast<std::size_t>(row_i)];
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::Text("0x%08X", tr.token);
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(tr.type_namespace.c_str());
                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextUnformatted(tr.type_name.c_str());
                    ImGui::TableSetColumnIndex(3);
                    ImGui::TextUnformatted(tr.resolution_scope_summary.c_str());
                }
            }
            ImGui::EndTable();
        }
    }
}

void ClrMetadataPanel::render_types_and_cil_tab(const peelf::ClrMetadata& md) {
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x * 0.55f);
    if (ImGui::InputTextWithHint(
            "##ClrTypesFilter",
            "Filter TypeDef / MethodDef / Field / signature / token...",
            types_filter_buf_,
            sizeof(types_filter_buf_))) {
        types_filter_dirty_ = true;
    }
    ImGui::SameLine();
    if (ImGui::Checkbox("IL methods only", &methods_with_il_only_)) {
        types_filter_dirty_ = true;
    }
    if (types_filter_dirty_) {
        rebuild_filtered_member_rows();
    }
    ImGui::SameLine();
    ImGui::TextDisabled("(%zu / %zu)", filtered_member_indices_.size(), all_member_rows_.size());

    const ImVec2 avail = ImGui::GetContentRegionAvail();
    const bool side_by_side = avail.x >= ImGui::GetFontSize() * 52.0f;
    const ImVec2 list_size = side_by_side
                                 ? ImVec2(avail.x * 0.44f, std::max(avail.y, 120.0f))
                                 : ImVec2(0.0f, std::max(avail.y * 0.42f, 140.0f));

    if (ImGui::BeginChild("##ClrMembersPane", list_size, ImGuiChildFlags_Borders)) {
        if (ImGui::BeginTable(
                "##ClrMembersTable",
                4,
                ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
                    ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Token", ImGuiTableColumnFlags_WidthFixed, 86.0f);
            ImGui::TableSetupColumn("Type / Member", ImGuiTableColumnFlags_WidthStretch, 1.35f);
            ImGui::TableSetupColumn("RVA", ImGuiTableColumnFlags_WidthFixed, 76.0f);
            ImGui::TableSetupColumn("Signature / Flags", ImGuiTableColumnFlags_WidthStretch, 1.65f);
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(filtered_member_indices_.size()));
            while (clipper.Step()) {
                for (int vis_i = clipper.DisplayStart; vis_i < clipper.DisplayEnd; ++vis_i) {
                    const std::size_t row_idx =
                        filtered_member_indices_[static_cast<std::size_t>(vis_i)];
                    const MemberRow& row = all_member_rows_[row_idx];
                    const bool is_selected =
                        row.kind == MemberRowKind::Method &&
                        selected_method_index_.has_value() &&
                        *selected_method_index_ == row.index;

                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::PushID(static_cast<int>(row_idx));
                    const std::string tok_str = std::format("0x{:08X}", row.token);
                    if (ImGui::Selectable(
                            tok_str.c_str(),
                            is_selected,
                            ImGuiSelectableFlags_SpanAllColumns)) {
                        if (row.kind == MemberRowKind::Method) {
                            select_method_index(row.index, md);
                        } else if (row.kind == MemberRowKind::TypeDef &&
                                   row.index < md.type_defs.size()) {
                            const peelf::ClrTypeDef& td = md.type_defs[row.index];
                            if (td.method_count > 0u &&
                                static_cast<std::size_t>(td.method_start_index) < md.methods.size()) {
                                select_method_index(
                                    static_cast<std::size_t>(td.method_start_index), md);
                            }
                        }
                    }
                    ImGui::PopID();

                    ImGui::TableSetColumnIndex(1);
                    if (row.kind == MemberRowKind::TypeDef) {
                        ImGui::TextColored(
                            ImVec4(0.55f, 0.82f, 0.98f, 1.0f), "%s", row.display_name.c_str());
                    } else if (row.kind == MemberRowKind::Field) {
                        ImGui::TextDisabled("%s", row.display_name.c_str());
                    } else {
                        ImGui::TextUnformatted(row.display_name.c_str());
                    }

                    ImGui::TableSetColumnIndex(2);
                    if (row.rva != 0u) {
                        ImGui::Text("0x%X", row.rva);
                    } else {
                        ImGui::TextDisabled("-");
                    }

                    ImGui::TableSetColumnIndex(3);
                    ImGui::TextUnformatted(row.detail.c_str());
                }
            }
            ImGui::EndTable();
        }
    }
    ImGui::EndChild();

    if (side_by_side) {
        ImGui::SameLine();
    }

    if (ImGui::BeginChild("##ClrCilPane", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders)) {
        render_cil_pane(md);
    }
    ImGui::EndChild();
}

void ClrMetadataPanel::render_cil_pane(const peelf::ClrMetadata& md) {
    if (!selected_method_index_.has_value() || *selected_method_index_ >= md.methods.size()) {
        ImGui::TextDisabled("Select a MethodDef row to disassemble its ECMA-335 CIL method body.");
        return;
    }

    const peelf::ClrMethodDef& method = md.methods[*selected_method_index_];
    ImGui::TextColored(ImVec4(0.62f, 0.88f, 0.65f, 1.0f), "%s", method.full_name().c_str());
    if (method.file_offset.has_value() && on_navigate_offset_) {
        ImGui::SameLine();
        if (ImGui::SmallButton("Jump to Hex View")) {
            const std::size_t span_len =
                cached_cil_body_.has_value()
                    ? std::max<std::size_t>(
                          static_cast<std::size_t>(cached_cil_body_->header_size()) +
                              static_cast<std::size_t>(cached_cil_body_->code_size),
                          1u)
                    : 16u;
            selection_ = ViewerSelection{
                .kind = SelectionKind::ByteRange,
                .label = std::format("CIL: {}", method.full_name()),
                .file_offset = method.file_offset,
                .virtual_address =
                    model_.image() != nullptr
                        ? std::optional<std::uint64_t>(model_.image()->image_base() + method.rva)
                        : std::nullopt,
                .size = span_len,
                .preferred_view = PreferredView::Hex,
            };
            on_navigate_offset_(*method.file_offset, span_len);
        }
    }

    ImGui::TextWrapped("%s", method.signature_summary.c_str());
    if (method.file_offset.has_value()) {
        ImGui::TextDisabled(
            "Token 0x%08X | RVA 0x%X (file +0x%llX) | %s | impl: 0x%04X",
            method.token,
            method.rva,
            static_cast<unsigned long long>(*method.file_offset),
            method.flags_summary.c_str(),
            static_cast<unsigned int>(method.impl_flags));
    } else {
        ImGui::TextDisabled(
            "Token 0x%08X | RVA 0x%X | %s | impl: 0x%04X",
            method.token,
            method.rva,
            method.flags_summary.c_str(),
            static_cast<unsigned int>(method.impl_flags));
    }

    ImGui::Separator();

    if (!cached_cil_body_.has_value()) {
        ImGui::TextDisabled(
            "%s",
            cached_cil_error_.empty() ? "No CIL method body available." : cached_cil_error_.c_str());
        return;
    }

    const peelf::CilMethodBody& cil = *cached_cil_body_;
    ImGui::TextDisabled(
        "%s IL Header (%uB) | CodeSize %uB | MaxStack %u | LocalVarSigTok 0x%08X%s",
        cil.is_fat_header ? "Fat" : "Tiny",
        static_cast<unsigned int>(cil.header_size()),
        cil.code_size,
        static_cast<unsigned int>(cil.max_stack),
        cil.local_var_sig_tok,
        cil.init_locals ? " | InitLocals" : "");

    for (const std::string& diag : cil.diagnostics) {
        ImGui::TextColored(ImVec4(0.95f, 0.68f, 0.25f, 1.0f), "Note: %s", diag.c_str());
    }

    if (!cil.eh_clauses.empty()) {
        const std::string eh_hdr =
            std::format("Exception Handling Clauses ({})###CilEhHdr", cil.eh_clauses.size());
        if (ImGui::CollapsingHeader(eh_hdr.c_str(), ImGuiTreeNodeFlags_DefaultOpen)) {
            if (ImGui::BeginTable(
                    "##CilEhTable",
                    4,
                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
                ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 72.0f);
                ImGui::TableSetupColumn("Try Range", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                ImGui::TableSetupColumn("Handler Range", ImGuiTableColumnFlags_WidthFixed, 150.0f);
                ImGui::TableSetupColumn("Catch Type / Filter", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();
                for (const peelf::CilEhClause& eh : cil.eh_clauses) {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::TextUnformatted(peelf::to_string(eh.kind).data());
                    ImGui::TableSetColumnIndex(1);
                    ImGui::Text(
                        "IL_%04X..IL_%04X",
                        eh.try_offset,
                        eh.try_offset + eh.try_length);
                    ImGui::TableSetColumnIndex(2);
                    ImGui::Text(
                        "IL_%04X..IL_%04X",
                        eh.handler_offset,
                        eh.handler_offset + eh.handler_length);
                    ImGui::TableSetColumnIndex(3);
                    if (eh.kind == peelf::CilEhClauseKind::Catch) {
                        ImGui::Text(
                            "%s (0x%08X)",
                            eh.catch_type_name.c_str(),
                            eh.class_token_or_filter_offset);
                    } else if (eh.kind == peelf::CilEhClauseKind::Filter) {
                        ImGui::Text("filter @ IL_%04X", eh.class_token_or_filter_offset);
                    } else {
                        ImGui::TextDisabled("-");
                    }
                }
                ImGui::EndTable();
            }
        }
    }

    if (code_font_ != nullptr) {
        ImGui::PushFont(code_font_);
    }

    if (ImGui::BeginTable(
            "##CilDisasmTable",
            4,
            ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 82.0f);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("Mnemonic", ImGuiTableColumnFlags_WidthFixed, 118.0f);
        ImGui::TableSetupColumn("Operand", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(cil.instructions.size()));
        while (clipper.Step()) {
            for (int ins_i = clipper.DisplayStart; ins_i < clipper.DisplayEnd; ++ins_i) {
                const peelf::CilInstruction& ins =
                    cil.instructions[static_cast<std::size_t>(ins_i)];
                const bool is_target =
                    highlighted_il_offset_.has_value() &&
                    *highlighted_il_offset_ == ins.il_offset;

                ImGui::TableNextRow();
                if (is_target) {
                    ImGui::TableSetBgColor(
                        ImGuiTableBgTarget_RowBg1, IM_COL32(60, 110, 75, 110));
                }

                ImGui::TableSetColumnIndex(0);
                ImGui::PushID(ins_i);
                const std::string il_lbl = std::format("IL_{:04X}", ins.il_offset);
                if (ImGui::Selectable(
                        il_lbl.c_str(),
                        is_target,
                        ImGuiSelectableFlags_SpanAllColumns)) {
                    highlighted_il_offset_ = ins.branch_target_il_offset.value_or(ins.il_offset);
                }
                if (ImGui::BeginPopupContextItem("##CilRowCtx")) {
                    if (ImGui::MenuItem("Copy Instruction")) {
                        const std::string line =
                            ins.operand_text.empty()
                                ? std::format("IL_{:04X}: {}", ins.il_offset, ins.mnemonic)
                                : std::format(
                                      "IL_{:04X}: {} {}",
                                      ins.il_offset,
                                      ins.mnemonic,
                                      ins.operand_text);
                        ImGui::SetClipboardText(line.c_str());
                    }
                    if (method.file_offset.has_value() && on_navigate_offset_ &&
                        ImGui::MenuItem("Jump Instruction in Hex View")) {
                        const std::uint64_t ins_file_off =
                            *method.file_offset + cil.header_size() + ins.il_offset;
                        on_navigate_offset_(
                            ins_file_off, std::max<std::size_t>(ins.size, 1u));
                    }
                    ImGui::EndPopup();
                }
                ImGui::PopID();

                ImGui::TableSetColumnIndex(1);
                ImGui::TextDisabled("%s", ins.raw_bytes_hex.c_str());

                ImGui::TableSetColumnIndex(2);
                ImGui::TextColored(
                    ImVec4(0.75f, 0.86f, 1.0f, 1.0f), "%s", ins.mnemonic.c_str());

                ImGui::TableSetColumnIndex(3);
                if (!ins.operand_text.empty()) {
                    const std::string clean_op = escape_single_line(ins.operand_text, 240u);
                    ImGui::TextUnformatted(clean_op.c_str());
                }
            }
        }
        ImGui::EndTable();
    }

    if (code_font_ != nullptr) {
        ImGui::PopFont();
    }
}

void ClrMetadataPanel::render_pinvoke_tab(const peelf::ClrMetadata& md) {
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x * 0.6f);
    ImGui::InputTextWithHint(
        "##ClrPInvokeFilter",
        "Filter native DLL, unmanaged entry point, or managed method...",
        pinvoke_filter_buf_,
        sizeof(pinvoke_filter_buf_));

    if (md.pinvoke_entries.empty()) {
        ImGui::Spacing();
        ImGui::TextDisabled("No ECMA-335 ImplMap (P/Invoke) unmanaged imports are declared in this assembly.");
        return;
    }

    const std::string_view query(pinvoke_filter_buf_);
    std::vector<std::size_t> matching;
    matching.reserve(md.pinvoke_entries.size());
    for (std::size_t i = 0; i < md.pinvoke_entries.size(); ++i) {
        const peelf::ClrPInvokeEntry& pi = md.pinvoke_entries[i];
        const std::string flags_str = pi.flags_summary();
        if (!query.empty() &&
            !icontains_ascii(pi.module_name, query) &&
            !icontains_ascii(pi.entry_point_name, query) &&
            !icontains_ascii(pi.method_full_name, query) &&
            !icontains_ascii(flags_str, query)) {
            continue;
        }
        matching.push_back(i);
    }

    if (ImGui::BeginTable(
            "##ClrPInvokeTable",
            5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Token", ImGuiTableColumnFlags_WidthFixed, 92.0f);
        ImGui::TableSetupColumn("Native DLL", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("Entry Point", ImGuiTableColumnFlags_WidthStretch, 1.1f);
        ImGui::TableSetupColumn("Managed Method", ImGuiTableColumnFlags_WidthStretch, 1.5f);
        ImGui::TableSetupColumn("CallingConv / CharSet", ImGuiTableColumnFlags_WidthStretch, 1.1f);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(matching.size()));
        while (clipper.Step()) {
            for (int vis_i = clipper.DisplayStart; vis_i < clipper.DisplayEnd; ++vis_i) {
                const peelf::ClrPInvokeEntry& pi =
                    md.pinvoke_entries[matching[static_cast<std::size_t>(vis_i)]];
                const std::string flags_str = pi.flags_summary();
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Text("0x%08X", pi.method_token);
                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(
                    ImVec4(0.95f, 0.72f, 0.38f, 1.0f), "%s", pi.module_name.c_str());
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(pi.entry_point_name.c_str());
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(pi.method_full_name.c_str());
                ImGui::TableSetColumnIndex(4);
                ImGui::TextUnformatted(flags_str.c_str());
            }
        }
        ImGui::EndTable();
    }
}

void ClrMetadataPanel::render_user_strings_tab(const peelf::ClrMetadata& md) {
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x * 0.6f);
    ImGui::InputTextWithHint(
        "##ClrUsFilter",
        "Filter #US literal string or 0x70xxxxxx token...",
        us_filter_buf_,
        sizeof(us_filter_buf_));

    if (md.user_strings.empty()) {
        ImGui::Spacing();
        ImGui::TextDisabled("No non-empty user string literals were found in the #US heap.");
        return;
    }

    const std::string_view query(us_filter_buf_);
    std::vector<std::size_t> matching;
    matching.reserve(md.user_strings.size());
    for (std::size_t i = 0; i < md.user_strings.size(); ++i) {
        const peelf::ClrUserString& us = md.user_strings[i];
        if (!query.empty()) {
            const std::string tok_hex = std::format("0x{:08X}", us.token);
            if (!icontains_ascii(us.value, query) && !icontains_ascii(tok_hex, query)) {
                continue;
            }
        }
        matching.push_back(i);
    }

    if (ImGui::BeginTable(
            "##ClrUsTable",
            3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Token", ImGuiTableColumnFlags_WidthFixed, 96.0f);
        ImGui::TableSetupColumn("Chars (UTF-8B)", ImGuiTableColumnFlags_WidthFixed, 110.0f);
        ImGui::TableSetupColumn("String Literal", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(matching.size()));
        while (clipper.Step()) {
            for (int vis_i = clipper.DisplayStart; vis_i < clipper.DisplayEnd; ++vis_i) {
                const peelf::ClrUserString& us =
                    md.user_strings[matching[static_cast<std::size_t>(vis_i)]];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::PushID(vis_i);
                const std::string tok_lbl = std::format("0x{:08X}", us.token);
                if (ImGui::Selectable(
                        tok_lbl.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                    ImGui::SetClipboardText(us.value.c_str());
                }
                ImGui::PopID();
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%zu", us.value.size());
                ImGui::TableSetColumnIndex(2);
                const std::string escaped = escape_single_line(us.value, 320u);
                ImGui::TextUnformatted(escaped.c_str());
            }
        }
        ImGui::EndTable();
    }
}

} // namespace viewer
