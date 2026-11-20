// SPDX-License-Identifier: BSD-2-Clause
#include "ui_panels_signatures.hpp"

#include <imgui.h>

#include <algorithm>
#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <format>
#include <limits>
#include <optional>
#include <string_view>
#include <utility>

namespace viewer {
namespace {

constexpr std::string_view kDefaultInlineRuleTemplate =
    "// Custom YARA-Lite rules (live-compiled with line:col diagnostics)\n"
    "// Example:\n"
    "// rule Custom_MZ_Check : custom {\n"
    "//   meta:\n"
    "//     description = \"Checks for MZ magic\"\n"
    "//     severity = \"note\"\n"
    "//   strings:\n"
    "//     $mz = { 4D 5A }\n"
    "//   condition:\n"
    "//     $mz at 0\n"
    "// }\n";

[[nodiscard]] char ascii_lower(char c) noexcept {
    if (c >= 'A' && c <= 'Z') {
        return static_cast<char>(c - 'A' + 'a');
    }
    return c;
}

[[nodiscard]] bool icontains_sv(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    if (needle.size() > haystack.size()) {
        return false;
    }
    for (std::size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
        bool ok = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            if (ascii_lower(haystack[i + j]) != ascii_lower(needle[j])) {
                ok = false;
                break;
            }
        }
        if (ok) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] int icompare_sv(std::string_view a, std::string_view b) noexcept {
    const std::size_t n = std::min(a.size(), b.size());
    for (std::size_t i = 0; i < n; ++i) {
        const char ca = ascii_lower(a[i]);
        const char cb = ascii_lower(b[i]);
        if (ca != cb) {
            return ca < cb ? -1 : 1;
        }
    }
    if (a.size() == b.size()) {
        return 0;
    }
    return a.size() < b.size() ? -1 : 1;
}

[[nodiscard]] int confidence_rank(std::string_view conf) noexcept {
    if (icontains_sv(conf, "high")) {
        return 3;
    }
    if (icontains_sv(conf, "medium")) {
        return 2;
    }
    return 1;
}

[[nodiscard]] ImVec4 confidence_color(std::string_view conf) noexcept {
    const int rank = confidence_rank(conf);
    if (rank >= 3) {
        return ImVec4(0.32f, 0.88f, 0.52f, 1.0f);
    }
    if (rank == 2) {
        return ImVec4(0.95f, 0.78f, 0.30f, 1.0f);
    }
    return ImVec4(0.95f, 0.48f, 0.36f, 1.0f);
}

[[nodiscard]] ImVec4 severity_color(std::string_view sev) noexcept {
    if (icontains_sv(sev, "error") || icontains_sv(sev, "critical") || icontains_sv(sev, "high")) {
        return ImVec4(0.96f, 0.36f, 0.36f, 1.0f);
    }
    if (icontains_sv(sev, "note") || icontains_sv(sev, "info") || icontains_sv(sev, "low")) {
        return ImVec4(0.45f, 0.80f, 0.98f, 1.0f);
    }
    return ImVec4(0.96f, 0.76f, 0.28f, 1.0f);
}

[[nodiscard]] bool section_is_executable(const BinaryModel& model,
                                         std::optional<std::uint64_t> va) noexcept {
    if (!va.has_value() || model.image() == nullptr) {
        return false;
    }
    for (const peelf::Section& sec : model.image()->sections()) {
        const std::uint64_t span = std::max(sec.file_size, sec.virtual_size);
        if (span != 0u && *va >= sec.virtual_address && (*va - sec.virtual_address) < span) {
            return sec.executable;
        }
    }
    return false;
}

enum CryptoSortColumn : ImGuiID {
    kColCryptoCategory = 1,
    kColCryptoAlgorithm = 2,
    kColCryptoConfidence = 3,
    kColCryptoVa = 4,
    kColCryptoOffset = 5,
    kColCryptoSection = 6,
    kColCryptoFunction = 7,
};

struct PendingJumpRequest {
    std::optional<std::uint64_t> address{};
    PreferredView view{PreferredView::Hex};
    std::optional<std::uint64_t> file_offset{};
    std::size_t byte_length{1};
    std::string label{};
};

} // namespace

SignaturesPanel::SignaturesPanel(BinaryModel& model,
                                 const ReferenceIndex& references,
                                 ViewerSelection& selection,
                                 NavigateAddressCallback on_navigate_address,
                                 NavigateOffsetCallback on_navigate_offset)
    : UiPanel("Signatures & Crypto")
    , model_(model)
    , references_(references)
    , selection_(selection)
    , on_navigate_address_(std::move(on_navigate_address))
    , on_navigate_offset_(std::move(on_navigate_offset)) {
    const std::size_t copy_len =
        std::min(kDefaultInlineRuleTemplate.size(), inline_rules_buf_.size() - 1u);
    std::memcpy(inline_rules_buf_.data(), kDefaultInlineRuleTemplate.data(), copy_len);
    inline_rules_buf_[copy_len] = '\0';
    recompile_inline_rules();
}

void SignaturesPanel::recompile_inline_rules() {
    const std::string_view src(inline_rules_buf_.data());
    inline_parse_result_ = peelf::parse_signature_rules(src, "<inline>");
    inline_rules_compiled_ = true;
}

void SignaturesPanel::run_rule_scan() {
    if (!inline_rules_compiled_) {
        recompile_inline_rules();
    }

    peelf::SignatureRuleSet combined{};
    if (include_builtin_rules_) {
        const peelf::SignatureRuleSet& builtins = peelf::builtin_signature_rules();
        combined.rules.insert(
            combined.rules.end(), builtins.rules.begin(), builtins.rules.end());
    }
    for (const LoadedRulePack& pack : loaded_rule_files_) {
        combined.rules.insert(
            combined.rules.end(), pack.ruleset.rules.begin(), pack.ruleset.rules.end());
    }
    if (inline_parse_result_.ok()) {
        combined.rules.insert(combined.rules.end(),
                              inline_parse_result_.ruleset.rules.begin(),
                              inline_parse_result_.ruleset.rules.end());
    }

    rule_matches_ = model_.evaluate_yara_lite_rules(combined, scan_all_live_regions_);
    has_scanned_rules_ = true;
    rule_scan_status_ = std::format(
        "Evaluated {} rule(s) -> {} match(es)", combined.rules.size(), rule_matches_.size());
}

void SignaturesPanel::draw_contents() {
    if (model_.content_generation() != last_content_generation_ ||
        model_.edit_revision() != last_edit_revision_) {
        const bool generation_changed =
            (model_.content_generation() != last_content_generation_);
        const bool edit_changed = (model_.edit_revision() != last_edit_revision_);
        last_content_generation_ = model_.content_generation();
        last_edit_revision_ = model_.edit_revision();

        if (generation_changed) {
            selected_crypto_idx_ = static_cast<std::size_t>(-1);
            crypto_scan_status_.clear();
            rule_matches_.clear();
            has_scanned_rules_ = false;
            rule_scan_status_.clear();
        } else if (edit_changed && !model_.is_live_process()) {
            model_.refresh_signatures_and_crypto();
            if (has_scanned_rules_) {
                run_rule_scan();
            }
        }

        if (model_.has_file() && !has_scanned_rules_ && !model_.is_live_process()) {
            run_rule_scan();
        }
    }

    if (!model_.has_file()) {
        ImGui::TextDisabled(
            "Open a PE/ELF/Mach-O binary, crash dump, or live process to inspect crypto constants, "
            "YARA-lite signatures, and PE Rich headers.");
        return;
    }

    // Compact summary header
    ImGui::TextDisabled("Crypto/Packer Hits:");
    ImGui::SameLine();
    ImGui::Text("%zu", model_.crypto_signatures().size());
    ImGui::SameLine(0.0f, 16.0f);
    ImGui::TextDisabled("Rule Matches:");
    ImGui::SameLine();
    if (has_scanned_rules_) {
        ImGui::Text("%zu", rule_matches_.size());
    } else {
        ImGui::TextDisabled("not scanned");
    }
    const bool is_pe_target =
        model_.format() == BinaryFormat::PE || model_.pe_rich_header().has_value();
    if (is_pe_target) {
        ImGui::SameLine(0.0f, 16.0f);
        ImGui::TextDisabled("PE Rich:");
        ImGui::SameLine();
        if (const auto& rich = model_.pe_rich_header(); !rich.has_value()) {
            ImGui::TextDisabled("Not Present");
        } else if (rich->checksum_valid) {
            ImGui::TextColored(ImVec4(0.32f, 0.88f, 0.52f, 1.0f),
                               "Valid (%zu tool entries)",
                               rich->entries.size());
        } else {
            ImGui::TextColored(ImVec4(0.96f, 0.42f, 0.36f, 1.0f), "Checksum Mismatch");
        }
    }
    ImGui::Separator();

    if (ImGui::BeginTabBar("##SignaturesAndCryptoTabs")) {
        const std::string crypto_tab_label = std::format(
            "Crypto & Packer Constants ({})###CryptoTab", model_.crypto_signatures().size());
        if (ImGui::BeginTabItem(crypto_tab_label.c_str())) {
            render_crypto_tab();
            ImGui::EndTabItem();
        }

        const std::string yara_tab_label = has_scanned_rules_
            ? std::format("Rule Scanner (YARA-Lite) ({})###YaraTab", rule_matches_.size())
            : std::string("Rule Scanner (YARA-Lite)###YaraTab");
        if (ImGui::BeginTabItem(yara_tab_label.c_str())) {
            render_yara_tab();
            ImGui::EndTabItem();
        }

        if (is_pe_target) {
            if (ImGui::BeginTabItem("PE Rich Header###PeRichTab")) {
                render_pe_rich_tab();
                ImGui::EndTabItem();
            }
        }

        ImGui::EndTabBar();
    }
}

void SignaturesPanel::render_crypto_tab() {
    ImGui::SetNextItemWidth(240.0f);
    ImGui::InputTextWithHint("##CryptoFilter",
                             "Filter algorithm, summary, section, function...",
                             crypto_filter_buf_.data(),
                             crypto_filter_buf_.size());
    ImGui::SameLine();
    ImGui::SetNextItemWidth(175.0f);
    static constexpr std::array<const char*, 5> kCategoryItems = {
        "All Categories",
        "Symmetric Cipher",
        "Hash / Checksum",
        "Compression",
        "Packer",
    };
    ImGui::Combo("##CryptoCategory",
                 &crypto_category_filter_,
                 kCategoryItems.data(),
                 static_cast<int>(kCategoryItems.size()));

    if (model_.is_live_process()) {
        ImGui::SameLine();
        if (ImGui::Button("Scan Readable Regions")) {
            const std::size_t hits = model_.scan_live_process_crypto_signatures();
            crypto_scan_status_ = std::format("Scanned readable regions -> {} hit(s)", hits);
        }
        ImGui::SameLine();
        if (ImGui::Button("Active Module Only")) {
            model_.refresh_signatures_and_crypto();
            crypto_scan_status_ = std::format(
                "Scanned active module -> {} hit(s)", model_.crypto_signatures().size());
        }
    } else {
        ImGui::SameLine();
        if (ImGui::Button("Rescan")) {
            model_.refresh_signatures_and_crypto();
            crypto_scan_status_ =
                std::format("Rescanned image -> {} hit(s)", model_.crypto_signatures().size());
        }
    }
    if (!crypto_scan_status_.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("%s", crypto_scan_status_.c_str());
    }

    const std::span<const peelf::CryptoSignatureHit> hits = model_.crypto_signatures();
    const std::string_view filter_sv(crypto_filter_buf_.data());

    struct RowEntry {
        std::size_t index{0};
        std::optional<BinaryModel::ResolvedHitFunction> resolved_fn{};
    };
    std::vector<RowEntry> visible_rows{};
    visible_rows.reserve(hits.size());

    for (std::size_t i = 0; i < hits.size(); ++i) {
        const peelf::CryptoSignatureHit& h = hits[i];
        if (crypto_category_filter_ > 0 &&
            static_cast<std::size_t>(crypto_category_filter_) < kCategoryItems.size()) {
            const std::string_view expected_cat =
                kCategoryItems[static_cast<std::size_t>(crypto_category_filter_)];
            if (h.category != expected_cat) {
                continue;
            }
        }
        auto fn_info = model_.resolve_hit_referencing_function(
            h.virtual_address, h.byte_length, &references_);
        if (!filter_sv.empty()) {
            const std::string_view fn_name =
                fn_info.has_value() ? std::string_view(fn_info->display_name) : std::string_view{};
            if (!icontains_sv(h.algorithm, filter_sv) &&
                !icontains_sv(h.summary, filter_sv) &&
                !icontains_sv(h.section_name, filter_sv) &&
                !icontains_sv(h.id, filter_sv) &&
                !icontains_sv(h.category, filter_sv) &&
                !icontains_sv(fn_name, filter_sv)) {
                continue;
            }
        }
        visible_rows.push_back(RowEntry{.index = i, .resolved_fn = std::move(fn_info)});
    }

    ImGui::TextDisabled("Showing %zu / %zu signature hit(s)  |  Double-click row to jump, right-click for actions",
                        visible_rows.size(),
                        hits.size());

    std::optional<PendingJumpRequest> pending_jump{};
    std::optional<PendingEntityContextAction> pending_ctx{};

    if (ImGui::BeginTable("##CryptoHitsTable",
                          7,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable | ImGuiTableFlags_Sortable |
                              ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Category", ImGuiTableColumnFlags_WidthFixed, 128.0f, kColCryptoCategory);
        ImGui::TableSetupColumn("Algorithm", ImGuiTableColumnFlags_WidthFixed, 155.0f, kColCryptoAlgorithm);
        ImGui::TableSetupColumn("Confidence", ImGuiTableColumnFlags_WidthFixed, 82.0f, kColCryptoConfidence);
        ImGui::TableSetupColumn("VA", ImGuiTableColumnFlags_WidthFixed, 124.0f, kColCryptoVa);
        ImGui::TableSetupColumn(
            "Offset",
            ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthFixed,
            108.0f,
            kColCryptoOffset);
        ImGui::TableSetupColumn("Section", ImGuiTableColumnFlags_WidthFixed, 96.0f, kColCryptoSection);
        ImGui::TableSetupColumn("Function / Summary", ImGuiTableColumnFlags_WidthStretch, 1.0f, kColCryptoFunction);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs();
            sort_specs != nullptr && sort_specs->SpecsCount > 0) {
            const ImGuiTableColumnSortSpecs& spec = sort_specs->Specs[0];
            const bool asc = (spec.SortDirection != ImGuiSortDirection_Descending);
            std::ranges::sort(visible_rows, [&](const RowEntry& lhs, const RowEntry& rhs) {
                const peelf::CryptoSignatureHit& a = hits[lhs.index];
                const peelf::CryptoSignatureHit& b = hits[rhs.index];
                int cmp = 0;
                switch (spec.ColumnUserID) {
                case kColCryptoCategory:
                    cmp = icompare_sv(a.category, b.category);
                    break;
                case kColCryptoAlgorithm:
                    cmp = icompare_sv(a.algorithm, b.algorithm);
                    break;
                case kColCryptoConfidence:
                    cmp = confidence_rank(a.confidence) - confidence_rank(b.confidence);
                    break;
                case kColCryptoVa: {
                    const std::uint64_t va_a = a.virtual_address.value_or(0u);
                    const std::uint64_t va_b = b.virtual_address.value_or(0u);
                    cmp = (va_a == va_b) ? 0 : (va_a < va_b ? -1 : 1);
                    break;
                }
                case kColCryptoSection:
                    cmp = icompare_sv(a.section_name, b.section_name);
                    break;
                case kColCryptoFunction: {
                    const std::string_view fa = lhs.resolved_fn.has_value()
                        ? std::string_view(lhs.resolved_fn->display_name)
                        : std::string_view(a.summary);
                    const std::string_view fb = rhs.resolved_fn.has_value()
                        ? std::string_view(rhs.resolved_fn->display_name)
                        : std::string_view(b.summary);
                    cmp = icompare_sv(fa, fb);
                    break;
                }
                case kColCryptoOffset:
                default: {
                    const std::uint64_t off_a =
                        a.file_offset.value_or(std::numeric_limits<std::uint64_t>::max());
                    const std::uint64_t off_b =
                        b.file_offset.value_or(std::numeric_limits<std::uint64_t>::max());
                    cmp = (off_a == off_b) ? 0 : (off_a < off_b ? -1 : 1);
                    break;
                }
                }
                if (cmp == 0) {
                    const std::uint64_t off_a =
                        a.file_offset.value_or(a.virtual_address.value_or(0u));
                    const std::uint64_t off_b =
                        b.file_offset.value_or(b.virtual_address.value_or(0u));
                    if (off_a != off_b) {
                        return off_a < off_b;
                    }
                    return lhs.index < rhs.index;
                }
                return asc ? (cmp < 0) : (cmp > 0);
            });
            sort_specs->SpecsDirty = false;
        }

        for (std::size_t vis_i = 0; vis_i < visible_rows.size(); ++vis_i) {
            const RowEntry& row = visible_rows[vis_i];
            const peelf::CryptoSignatureHit& h = hits[row.index];
            const bool is_selected = (selected_crypto_idx_ == row.index);

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(row.index));

            if (ImGui::Selectable(h.category.c_str(),
                                  is_selected,
                                  ImGuiSelectableFlags_SpanAllColumns |
                                      ImGuiSelectableFlags_AllowDoubleClick)) {
                selected_crypto_idx_ = row.index;
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                    PendingJumpRequest req{};
                    req.label = h.algorithm;
                    req.byte_length = static_cast<std::size_t>(
                        std::clamp<std::uint64_t>(h.byte_length, 1u, 65536u));
                    if (!model_.is_live_process()) {
                        req.file_offset = h.file_offset;
                    }
                    if (row.resolved_fn.has_value()) {
                        req.address = row.resolved_fn->code_va;
                        req.view = PreferredView::Disassembly;
                    } else if (h.virtual_address.has_value() &&
                               section_is_executable(model_, h.virtual_address)) {
                        req.address = *h.virtual_address;
                        req.view = PreferredView::Disassembly;
                    } else if (h.virtual_address.has_value()) {
                        req.address = *h.virtual_address;
                        req.view = PreferredView::Hex;
                    }
                    pending_jump = std::move(req);
                }
            }

            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::Text("%s (%s)", h.algorithm.c_str(), h.id.c_str());
                ImGui::TextDisabled("%s", h.summary.c_str());
                ImGui::Text("Length: %" PRIu64 " byte(s)", h.byte_length);
                if (row.resolved_fn.has_value()) {
                    ImGui::Text("Function: %s%s (0x%" PRIX64 ")",
                                row.resolved_fn->display_name.c_str(),
                                row.resolved_fn->via_xref ? " [via XRef]" : "",
                                row.resolved_fn->code_va);
                }
                ImGui::EndTooltip();
            }

            draw_inspectable_entity_context_menu(
                "##crypto_row_ctx", model_, pending_ctx, [&]() -> InspectableEntity {
                    InspectableEntity entity{};
                    entity.va = h.virtual_address;
                    if (!model_.is_live_process()) {
                        entity.file_offset = h.file_offset;
                    }
                    entity.size = std::max<std::uint64_t>(h.byte_length, 1u);
                    entity.symbol_or_label = h.algorithm;
                    entity.module_name = h.section_name;
                    entity.extra_json_fields = {
                        {"signature_id", h.id},
                        {"category", h.category},
                        {"confidence", h.confidence},
                        {"summary", h.summary},
                    };
                    if (row.resolved_fn.has_value()) {
                        entity.extra_json_fields.emplace_back("referencing_function",
                                                              row.resolved_fn->display_name);
                    }
                    return entity;
                });

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(h.algorithm.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(confidence_color(h.confidence), "%s", h.confidence.c_str());

            ImGui::TableNextColumn();
            if (h.virtual_address.has_value()) {
                ImGui::Text("0x%" PRIX64, *h.virtual_address);
            } else {
                ImGui::TextDisabled("—");
            }

            ImGui::TableNextColumn();
            if (h.file_offset.has_value()) {
                ImGui::Text("0x%" PRIX64 " (%" PRIu64 "B)", *h.file_offset, h.byte_length);
            } else {
                ImGui::TextDisabled("— (%" PRIu64 "B)", h.byte_length);
            }

            ImGui::TableNextColumn();
            if (!h.section_name.empty()) {
                ImGui::TextUnformatted(h.section_name.c_str());
            } else {
                ImGui::TextDisabled("—");
            }

            ImGui::TableNextColumn();
            if (row.resolved_fn.has_value()) {
                if (ImGui::SmallButton("Disasm")) {
                    pending_jump = PendingJumpRequest{
                        .address = row.resolved_fn->code_va,
                        .view = PreferredView::Disassembly,
                        .file_offset = !model_.is_live_process() ? h.file_offset : std::nullopt,
                        .byte_length = static_cast<std::size_t>(
                            std::clamp<std::uint64_t>(h.byte_length, 1u, 65536u)),
                        .label = row.resolved_fn->display_name,
                    };
                }
                ImGui::SameLine();
                ImGui::Text("%s%s  —  %s",
                            row.resolved_fn->display_name.c_str(),
                            row.resolved_fn->via_xref ? " [xref]" : "",
                            h.summary.c_str());
            } else {
                ImGui::TextDisabled("%s", h.summary.c_str());
            }

            ImGui::PopID();
        }

        ImGui::EndTable();
    }

    if (pending_jump.has_value()) {
        if (pending_jump->file_offset.has_value() && on_navigate_offset_) {
            on_navigate_offset_(*pending_jump->file_offset, pending_jump->byte_length);
        }
        if (pending_jump->address.has_value() && on_navigate_address_) {
            on_navigate_address_(*pending_jump->address, pending_jump->view);
        }
        selection_ = ViewerSelection{
            .kind = SelectionKind::ByteRange,
            .label = pending_jump->label,
            .file_offset = pending_jump->file_offset,
            .virtual_address = pending_jump->address,
            .size = pending_jump->byte_length,
            .preferred_view = pending_jump->view,
        };
    }
    if (pending_ctx.has_value() && on_context_action_) {
        on_context_action_(pending_ctx->kind, pending_ctx->entity);
    }
}

void SignaturesPanel::render_yara_tab() {
    const std::size_t builtin_count = peelf::builtin_signature_rules().rules.size();
    const std::string builtin_label =
        std::format("Built-in Rules ({})", builtin_count);
    if (ImGui::Checkbox(builtin_label.c_str(), &include_builtin_rules_)) {
        run_rule_scan();
    }

    if (model_.is_live_process()) {
        ImGui::SameLine();
        if (ImGui::Checkbox("All Readable Regions", &scan_all_live_regions_)) {
            run_rule_scan();
        }
    }

    ImGui::SameLine();
    if (ImGui::Button("Scan Target")) {
        run_rule_scan();
    }
    if (!rule_scan_status_.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("%s", rule_scan_status_.c_str());
    }

    // External .yar / .rules file loader bar
    ImGui::SetNextItemWidth(320.0f);
    ImGui::InputTextWithHint("##RuleFilePath",
                             "Path to .yar / .yara / .rules file...",
                             rule_file_path_buf_.data(),
                             rule_file_path_buf_.size());
    ImGui::SameLine();
    if (ImGui::Button("Load Rules File")) {
        const std::filesystem::path p(rule_file_path_buf_.data());
        if (p.empty()) {
            rule_file_status_ = "Enter a .yar / .rules file path first.";
            rule_file_status_is_error_ = true;
        } else {
            auto loaded = peelf::load_signature_rules_file(p);
            if (!loaded.has_value()) {
                rule_file_status_ = loaded.error().message;
                rule_file_status_is_error_ = true;
            } else if (!loaded->ok()) {
                const auto& d = loaded->diagnostics.front();
                rule_file_status_ = std::format(
                    "{}:{}:{}: {}", d.source_name, d.line, d.column, d.message);
                rule_file_status_is_error_ = true;
            } else {
                const std::size_t added = loaded->ruleset.rules.size();
                loaded_rule_files_.push_back(LoadedRulePack{
                    .path = p,
                    .ruleset = std::move(loaded->ruleset),
                });
                rule_file_status_ = std::format(
                    "Loaded {} rule(s) from '{}'", added, p.filename().string());
                rule_file_status_is_error_ = false;
                run_rule_scan();
            }
        }
    }
    if (!loaded_rule_files_.empty()) {
        ImGui::SameLine();
        const std::string clear_label =
            std::format("Clear Files ({})", loaded_rule_files_.size());
        if (ImGui::Button(clear_label.c_str())) {
            loaded_rule_files_.clear();
            rule_file_status_ = "Cleared loaded rule files.";
            rule_file_status_is_error_ = false;
            run_rule_scan();
        }
    }
    if (!rule_file_status_.empty()) {
        ImGui::TextColored(rule_file_status_is_error_
                               ? ImVec4(0.96f, 0.40f, 0.36f, 1.0f)
                               : ImVec4(0.45f, 0.86f, 0.56f, 1.0f),
                           "%s",
                           rule_file_status_.c_str());
    }

    // Collapsible monospace inline YARA-lite editor with live line:col diagnostics
    if (ImGui::CollapsingHeader("Inline Custom Rules Editor (YARA-Lite)")) {
        if (code_font_ != nullptr) {
            ImGui::PushFont(code_font_, 0.0f);
        }
        const bool edited = ImGui::InputTextMultiline(
            "##InlineYaraRulesEditor",
            inline_rules_buf_.data(),
            inline_rules_buf_.size(),
            ImVec2(-1.0f, 150.0f),
            ImGuiInputTextFlags_AllowTabInput);
        if (code_font_ != nullptr) {
            ImGui::PopFont();
        }
        if (edited || !inline_rules_compiled_) {
            recompile_inline_rules();
        }

        if (inline_parse_result_.ok()) {
            ImGui::TextColored(ImVec4(0.36f, 0.88f, 0.54f, 1.0f),
                               "Compile OK: %zu inline custom rule(s) ready.",
                               inline_parse_result_.ruleset.rules.size());
        } else {
            for (const peelf::SignatureRuleDiagnostic& diag : inline_parse_result_.diagnostics) {
                ImGui::TextColored(ImVec4(0.96f, 0.38f, 0.36f, 1.0f),
                                   "[line %" PRIu32 ":%" PRIu32 "] %s",
                                   diag.line,
                                   diag.column,
                                   diag.message.c_str());
            }
        }
    }

    ImGui::Separator();

    std::optional<PendingJumpRequest> pending_jump{};
    std::optional<PendingEntityContextAction> pending_ctx{};

    if (ImGui::BeginTable("##YaraMatchesTable",
                          6,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Rule / Matched Patterns", ImGuiTableColumnFlags_WidthFixed, 250.0f);
        ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed, 76.0f);
        ImGui::TableSetupColumn("Tags", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("Hits", ImGuiTableColumnFlags_WidthFixed, 56.0f);
        ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 110.0f);
        ImGui::TableSetupColumn("Description / Location", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        for (std::size_t i = 0; i < rule_matches_.size(); ++i) {
            const peelf::SignatureRuleMatch& m = rule_matches_[i];
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(i));

            const ImGuiTreeNodeFlags node_flags =
                ImGuiTreeNodeFlags_SpanFullWidth |
                (m.string_matches.empty() ? ImGuiTreeNodeFlags_Leaf : ImGuiTreeNodeFlags_None);
            const bool open = ImGui::TreeNodeEx("##rule_node", node_flags, "%s", m.rule_name.c_str());

            ImGui::TableNextColumn();
            ImGui::TextColored(severity_color(m.severity), "%s", m.severity.c_str());

            ImGui::TableNextColumn();
            if (m.tags.empty()) {
                ImGui::TextDisabled("—");
            } else {
                std::string joined{};
                for (std::size_t t = 0; t < m.tags.size(); ++t) {
                    if (t > 0u) {
                        joined += ", ";
                    }
                    joined += m.tags[t];
                }
                ImGui::TextUnformatted(joined.c_str());
            }

            ImGui::TableNextColumn();
            ImGui::Text("%" PRIu64,
                        std::max<std::uint64_t>(m.total_match_count, m.string_matches.size()));

            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", m.source_name.c_str());

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(m.description.empty() ? m.rule_name.c_str() : m.description.c_str());

            if (open) {
                for (std::size_t j = 0; j < m.string_matches.size(); ++j) {
                    const peelf::SignatureStringMatch& sm = m.string_matches[j];
                    auto fn_info = model_.resolve_hit_referencing_function(
                        sm.virtual_address, sm.byte_length, &references_);

                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::PushID(static_cast<int>(j));
                    ImGui::Indent(14.0f);
                    if (sm.file_offset.has_value()) {
                        ImGui::TextColored(ImVec4(0.58f, 0.82f, 0.98f, 1.0f),
                                           "%s @ 0x%" PRIX64,
                                           sm.identifier.c_str(),
                                           *sm.file_offset);
                    } else {
                        ImGui::TextColored(
                            ImVec4(0.58f, 0.82f, 0.98f, 1.0f), "%s", sm.identifier.c_str());
                    }

                    draw_inspectable_entity_context_menu(
                        "##yara_hit_ctx", model_, pending_ctx, [&]() -> InspectableEntity {
                            InspectableEntity entity{};
                            entity.va = sm.virtual_address;
                            if (!model_.is_live_process()) {
                                entity.file_offset = sm.file_offset;
                            }
                            entity.size = std::max<std::uint64_t>(sm.byte_length, 1u);
                            entity.symbol_or_label = std::format("{}:{}", m.rule_name, sm.identifier);
                            entity.module_name = sm.section_name;
                            entity.extra_json_fields = {
                                {"rule", m.rule_name},
                                {"pattern", sm.identifier},
                                {"preview", sm.matched_preview},
                            };
                            return entity;
                        });
                    ImGui::Unindent(14.0f);

                    ImGui::TableNextColumn();
                    if (ImGui::SmallButton("Hex")) {
                        pending_jump = PendingJumpRequest{
                            .address = sm.virtual_address,
                            .view = PreferredView::Hex,
                            .file_offset = !model_.is_live_process() ? sm.file_offset : std::nullopt,
                            .byte_length = static_cast<std::size_t>(
                                std::clamp<std::uint64_t>(sm.byte_length, 1u, 65536u)),
                            .label = std::format("{}:{}", m.rule_name, sm.identifier),
                        };
                    }
                    if (sm.virtual_address.has_value() || fn_info.has_value()) {
                        ImGui::SameLine();
                        if (ImGui::SmallButton("Disasm")) {
                            const std::uint64_t target_va = fn_info.has_value()
                                ? fn_info->code_va
                                : *sm.virtual_address;
                            pending_jump = PendingJumpRequest{
                                .address = target_va,
                                .view = PreferredView::Disassembly,
                                .file_offset = !model_.is_live_process() ? sm.file_offset : std::nullopt,
                                .byte_length = static_cast<std::size_t>(
                                    std::clamp<std::uint64_t>(sm.byte_length, 1u, 65536u)),
                                .label = std::format("{}:{}", m.rule_name, sm.identifier),
                            };
                        }
                    }

                    ImGui::TableNextColumn();
                    if (sm.virtual_address.has_value()) {
                        ImGui::Text("VA 0x%" PRIX64, *sm.virtual_address);
                    } else {
                        ImGui::TextDisabled("—");
                    }

                    ImGui::TableNextColumn();
                    ImGui::Text("%" PRIu64 "B", sm.byte_length);

                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%s", sm.section_name.empty() ? "—" : sm.section_name.c_str());

                    ImGui::TableNextColumn();
                    if (fn_info.has_value()) {
                        ImGui::Text("%s%s  |  %s",
                                    fn_info->display_name.c_str(),
                                    fn_info->via_xref ? " [xref]" : "",
                                    sm.matched_preview.c_str());
                    } else {
                        ImGui::TextUnformatted(sm.matched_preview.c_str());
                    }

                    ImGui::PopID();
                }
                ImGui::TreePop();
            }

            ImGui::PopID();
        }

        ImGui::EndTable();
    }

    if (pending_jump.has_value()) {
        if (pending_jump->file_offset.has_value() && on_navigate_offset_) {
            on_navigate_offset_(*pending_jump->file_offset, pending_jump->byte_length);
        }
        if (pending_jump->address.has_value() && on_navigate_address_) {
            on_navigate_address_(*pending_jump->address, pending_jump->view);
        }
        selection_ = ViewerSelection{
            .kind = SelectionKind::ByteRange,
            .label = pending_jump->label,
            .file_offset = pending_jump->file_offset,
            .virtual_address = pending_jump->address,
            .size = pending_jump->byte_length,
            .preferred_view = pending_jump->view,
        };
    }
    if (pending_ctx.has_value() && on_context_action_) {
        on_context_action_(pending_ctx->kind, pending_ctx->entity);
    }
}

void SignaturesPanel::render_pe_rich_tab() {
    const auto& maybe_rich = model_.pe_rich_header();
    if (!maybe_rich.has_value()) {
        if (model_.format() == BinaryFormat::PE) {
            ImGui::TextDisabled("Status: Not Present (stubless or stripped Rich header)");
        } else {
            ImGui::TextDisabled("Target is not a PE image.");
        }
        return;
    }

    const peelf::PeRichHeader& rich = *maybe_rich;
    ImGui::TextDisabled("Status:");
    ImGui::SameLine();
    if (rich.checksum_valid) {
        ImGui::TextColored(ImVec4(0.32f, 0.88f, 0.52f, 1.0f), "Valid");
    } else {
        ImGui::TextColored(ImVec4(0.96f, 0.38f, 0.36f, 1.0f), "Checksum Mismatch");
        if (!rich.diagnostic.empty()) {
            ImGui::SameLine();
            ImGui::TextDisabled("(%s)", rich.diagnostic.c_str());
        }
    }

    ImGui::SameLine(0.0f, 18.0f);
    ImGui::Text("XOR Key: 0x%08" PRIX32, rich.xor_key);
    ImGui::SameLine(0.0f, 18.0f);
    ImGui::Text("Computed Checksum: 0x%08" PRIX32, rich.computed_checksum);
    ImGui::SameLine(0.0f, 18.0f);
    ImGui::TextDisabled("Span: [0x%" PRIX64 "..0x%" PRIX64 ")",
                        rich.dans_offset,
                        rich.rich_offset + 8u);

    if (!model_.is_live_process() && rich.rich_offset >= rich.dans_offset) {
        ImGui::SameLine();
        if (ImGui::SmallButton("Highlight in Hex View") && on_navigate_offset_) {
            const auto span_bytes =
                static_cast<std::size_t>((rich.rich_offset + 8u) - rich.dans_offset);
            on_navigate_offset_(rich.dans_offset, span_bytes);
        }
    }

    ImGui::Separator();

    std::optional<std::uint64_t> jump_entry_offset{};
    if (ImGui::BeginTable("##PeRichEntriesTable",
                          5,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Product ID", ImGuiTableColumnFlags_WidthFixed, 96.0f);
        ImGui::TableSetupColumn("Toolchain / Component", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("Build", ImGuiTableColumnFlags_WidthFixed, 84.0f);
        ImGui::TableSetupColumn("Count", ImGuiTableColumnFlags_WidthFixed, 84.0f);
        ImGui::TableSetupColumn("File Offset", ImGuiTableColumnFlags_WidthFixed, 108.0f);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        for (std::size_t i = 0; i < rich.entries.size(); ++i) {
            const peelf::PeRichCompIdEntry& e = rich.entries[i];
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(i));

            std::array<char, 32> prod_buf{};
            std::snprintf(prod_buf.data(), prod_buf.size(), "0x%04X (%u)", e.prod_id, e.prod_id);
            if (ImGui::Selectable(prod_buf.data(),
                                  false,
                                  ImGuiSelectableFlags_SpanAllColumns |
                                      ImGuiSelectableFlags_AllowDoubleClick)) {
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) &&
                    !model_.is_live_process()) {
                    jump_entry_offset = e.file_offset;
                }
            }

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(e.tool_category.c_str());

            ImGui::TableNextColumn();
            ImGui::Text("%u", e.build_number);

            ImGui::TableNextColumn();
            ImGui::Text("%" PRIu32, e.use_count);

            ImGui::TableNextColumn();
            ImGui::Text("0x%" PRIX64, e.file_offset);

            ImGui::PopID();
        }

        ImGui::EndTable();
    }

    if (jump_entry_offset.has_value() && on_navigate_offset_) {
        on_navigate_offset_(*jump_entry_offset, 8u);
    }
}

} // namespace viewer
