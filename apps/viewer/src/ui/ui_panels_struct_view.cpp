#include "ui_panels_struct_view.hpp"

#include <imgui.h>

#include <algorithm>
#include <array>
#include <cfloat>
#include <cinttypes>
#include <cstdio>
#include <format>

namespace viewer {
namespace {

int resize_custom_c_string_callback(ImGuiInputTextCallbackData* data) {
    if (data != nullptr && data->EventFlag == ImGuiInputTextFlags_CallbackResize) {
        auto* str = static_cast<std::string*>(data->UserData);
        if (str != nullptr) {
            str->resize(static_cast<std::size_t>(data->BufTextLen));
            data->Buf = str->data();
        }
    }
    return 0;
}

} // namespace

StructureViewPanel::StructureViewPanel(BinaryModel& model, const ViewerSelection& selection)
    : UiPanel("Structure View"),
      model_(model),
      selection_(selection),
      custom_c_buffer_(default_custom_c_types_template()) {}

void StructureViewPanel::apply_structure_at(std::string_view type_name,
                                            std::uint64_t address,
                                            bool is_file_offset,
                                            std::uint32_t count) {
    if (!type_name.empty()) {
        selected_type_name_ = std::string(type_name);
    }
    target_address_ = address;
    use_file_offset_ = model_.is_live_process() ? false : is_file_offset;
    array_count_ = static_cast<int>(std::clamp<std::uint32_t>(count, 1u, 64u));
    sync_with_selection_ = false;
    addr_mode_warning_.clear();
    dirty_ = true;
}

void StructureViewPanel::reset_for_new_binary() {
    evaluated_.reset();
    status_error_.clear();
    addr_mode_warning_.clear();
    selected_field_path_.clear();
    custom_c_editor_dirty_ = false;
    custom_c_diagnostics_.clear();
    custom_c_status_.clear();
    last_synced_structure_revision_ = 0;
    sync_custom_c_editor_from_model();
    dirty_ = true;

    if (model_.is_live_process()) {
        use_file_offset_ = false;
        target_address_ = model_.view_base_address();
    } else if (const peelf::IBinaryImage* img = model_.image()) {
        use_file_offset_ = true;
        target_address_ = 0;
        if (img->format() == peelf::Format::PE) {
            selected_type_name_ = "IMAGE_DOS_HEADER";
        } else if (img->format() == peelf::Format::ELF) {
            selected_type_name_ = img->is_64bit() ? "Elf64_Ehdr" : "Elf32_Ehdr";
        }
    } else {
        target_address_ = 0;
    }
}

void StructureViewPanel::sync_custom_c_editor_from_model() {
    last_synced_structure_revision_ = model_.structure_binding_revision();
    if (custom_c_editor_dirty_) {
        return;
    }
    if (!model_.custom_c_types_source().empty()) {
        custom_c_buffer_ = model_.custom_c_types_source();
        custom_c_abi_mode_ = std::clamp(static_cast<int>(model_.custom_c_types_abi()), 0, 2);
        custom_c_diagnostics_.clear();
        custom_c_status_ = std::format(
            "Active: {} custom C type(s).", model_.custom_types().size());
    } else {
        custom_c_buffer_ = std::string(default_custom_c_types_template());
        custom_c_abi_mode_ = 0;
        custom_c_diagnostics_.clear();
        custom_c_status_.clear();
    }
}

void StructureViewPanel::draw_custom_c_editor(std::span<const DataTypeRecord> extra_types) {
    if (!show_custom_c_editor_) {
        return;
    }

    ImGui::Separator();
    ImGui::TextUnformatted("Custom C Struct / Union / Enum / Typedef Declarations");
    ImGui::SameLine();
    ImGui::TextDisabled("(Persisted in .peproj)");

    static constexpr std::array<const char*, 3> kAbiItems = {
        "Auto from Target",
        "64-bit",
        "32-bit",
    };
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("Target ABI:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(150.0f);
    if (ImGui::Combo("##CustomCAbi",
                     &custom_c_abi_mode_,
                     kAbiItems.data(),
                     static_cast<int>(kAbiItems.size()))) {
        custom_c_editor_dirty_ = true;
    }

    const auto abi_enum = static_cast<CTypeAbiMode>(std::clamp(custom_c_abi_mode_, 0, 2));
    const peelf::TargetLayout target_layout = model_.target_layout();
    const bool eff_64 = (abi_enum == CTypeAbiMode::Bits64) ||
                        (abi_enum == CTypeAbiMode::AutoTarget && target_layout.is_64bit());
    const CLongModel long_model = model_.effective_c_long_model(abi_enum);
    ImGui::SameLine();
    ImGui::TextDisabled("(%u-byte ptr, %s)",
                        eff_64 ? 8u : 4u,
                        long_model == CLongModel::LP64 ? "LP64: 8B long" : "LLP64/ILP32: 4B long");

    ImGui::SameLine(0.0f, 14.0f);
    if (ImGui::Button("Compile & Add Types")) {
        CTypeParseResult res = model_.compile_and_set_custom_c_types(
            custom_c_buffer_, abi_enum, extra_types);
        custom_c_diagnostics_ = std::move(res.diagnostics);
        if (res.ok()) {
            custom_c_editor_dirty_ = false;
            last_synced_structure_revision_ = model_.structure_binding_revision();
            custom_c_status_ = std::format(
                "Compiled {} custom C type(s).", res.types.size());
            if (!res.types.empty()) {
                bool current_is_custom = false;
                for (const DataTypeRecord& r : res.types) {
                    if (r.name == selected_type_name_) {
                        current_is_custom = true;
                        break;
                    }
                }
                if (!current_is_custom) {
                    std::string preferred = res.types.front().name;
                    for (const DataTypeRecord& r : res.types) {
                        if (!r.is_enum) {
                            preferred = r.name;
                            break;
                        }
                    }
                    selected_type_name_ = std::move(preferred);
                }
            }
            dirty_ = true;
        } else {
            custom_c_status_.clear();
        }
    }

    ImGui::SameLine();
    if (ImGui::Button("Load Template")) {
        custom_c_buffer_ = std::string(default_custom_c_types_template());
        custom_c_diagnostics_.clear();
        custom_c_status_.clear();
        custom_c_editor_dirty_ = true;
    }

    ImGui::SameLine();
    const bool has_custom =
        !model_.custom_types().empty() || !model_.custom_c_types_source().empty();
    ImGui::BeginDisabled(!has_custom);
    if (ImGui::Button("Clear Custom Types")) {
        model_.clear_custom_c_types();
        custom_c_editor_dirty_ = false;
        sync_custom_c_editor_from_model();
        custom_c_status_ = "Cleared custom C types.";
        dirty_ = true;
    }
    ImGui::EndDisabled();

    ImGui::SameLine();
    if (ImGui::Button("Hide Editor")) {
        show_custom_c_editor_ = false;
    }

    if (focus_custom_c_editor_) {
        ImGui::SetKeyboardFocusHere();
        focus_custom_c_editor_ = false;
    }

    const float editor_h = std::max(ImGui::GetTextLineHeightWithSpacing() * 8.5f, 150.0f);
    if (code_font_ != nullptr) {
        ImGui::PushFont(code_font_, 0.0f);
    }
    if (ImGui::InputTextMultiline("##CustomCTypesSource",
                                  custom_c_buffer_.data(),
                                  custom_c_buffer_.capacity() + 1u,
                                  ImVec2(-FLT_MIN, editor_h),
                                  ImGuiInputTextFlags_AllowTabInput |
                                      ImGuiInputTextFlags_CallbackResize,
                                  resize_custom_c_string_callback,
                                  &custom_c_buffer_)) {
        custom_c_editor_dirty_ = true;
    }
    if (code_font_ != nullptr) {
        ImGui::PopFont();
    }

    for (const CTypeParseDiagnostic& diag : custom_c_diagnostics_) {
        const ImVec4 col = (diag.severity == CTypeDiagnosticSeverity::Warning)
            ? ImVec4(0.95f, 0.78f, 0.30f, 1.0f)
            : ImVec4(0.95f, 0.42f, 0.42f, 1.0f);
        ImGui::TextColored(
            col,
            "Line %" PRIu32 ", Col %" PRIu32 ": %s",
            diag.line,
            diag.column,
            diag.message.c_str());
    }
    if (custom_c_diagnostics_.empty() && !custom_c_status_.empty()) {
        ImGui::TextColored(ImVec4(0.40f, 0.88f, 0.55f, 1.0f), "%s", custom_c_status_.c_str());
    }
    ImGui::Separator();
}

void StructureViewPanel::ensure_default_type_selected(const StructureCatalog& catalog) {
    if (!selected_type_name_.empty() && catalog.find(selected_type_name_) != nullptr) {
        return;
    }
    if (const peelf::IBinaryImage* img = model_.image()) {
        if (img->format() == peelf::Format::PE && catalog.find("IMAGE_DOS_HEADER") != nullptr) {
            selected_type_name_ = "IMAGE_DOS_HEADER";
            return;
        }
        if (img->format() == peelf::Format::ELF) {
            const char* ehdr = img->is_64bit() ? "Elf64_Ehdr" : "Elf32_Ehdr";
            if (catalog.find(ehdr) != nullptr) {
                selected_type_name_ = ehdr;
                return;
            }
        }
    }
    if (!catalog.empty()) {
        selected_type_name_ = catalog.entries().front().record.name;
    }
}

void StructureViewPanel::reevaluate(const StructureCatalog& catalog) {
    dirty_ = false;
    last_eval_revision_ = model_.edit_revision();
    status_error_.clear();

    if (!model_.has_file()) {
        evaluated_.reset();
        return;
    }

    ensure_default_type_selected(catalog);
    if (selected_type_name_.empty()) {
        evaluated_.reset();
        return;
    }

    peelf::TargetLayout layout = model_.target_layout();
    if (endian_override_ == 1) {
        layout.endianness = peelf::Endianness::Little;
    } else if (endian_override_ == 2) {
        layout.endianness = peelf::Endianness::Big;
    }
    if (width_override_ == 1) {
        layout.address_width = peelf::AddressWidth::Bits32;
    } else if (width_override_ == 2) {
        layout.address_width = peelf::AddressWidth::Bits64;
    }

    StructureEvalOptions opts{
        .layout = layout,
        .count = static_cast<std::uint32_t>(std::clamp(array_count_, 1, 64)),
        .max_depth = 8,
        .max_array_elements = 64,
        .max_pointer_deref_depth = 2,
        .dereference_struct_pointers = true,
    };

    const bool eff_file_off = model_.is_live_process() ? false : use_file_offset_;
    BinaryModelStructureByteSource src(model_);
    auto res = evaluate_structure(catalog, selected_type_name_, target_address_, eff_file_off, src, opts);
    if (res) {
        evaluated_ = std::move(*res);
    } else {
        evaluated_.reset();
        status_error_ = res.error().message;
    }
}

void StructureViewPanel::draw_field_rows(std::span<const EvaluatedField> fields,
                                         const StructureCatalog& catalog,
                                         int depth) {
    for (std::size_t idx = 0; idx < fields.size(); ++idx) {
        const EvaluatedField& f = fields[idx];
        ImGui::PushID(static_cast<int>(idx));

        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);

        const bool has_children = !f.children.empty();
        ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_SpanFullWidth | ImGuiTreeNodeFlags_OpenOnArrow;
        if (!has_children) {
            flags |= ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen;
        }
        if (depth == 0 && fields.size() <= 4 && f.name.starts_with('[')) {
            flags |= ImGuiTreeNodeFlags_DefaultOpen;
        }

        const std::string row_key = std::format("{}:{}:{}", depth, f.address, f.name);
        if (selected_field_path_ == row_key) {
            flags |= ImGuiTreeNodeFlags_Selected;
        }

        const bool open = ImGui::TreeNodeEx("##field", flags, "%s", f.name.c_str());
        if (ImGui::IsItemClicked() && !ImGui::IsItemToggledOpen()) {
            selected_field_path_ = row_key;
            if (on_field_selected_) {
                on_field_selected_(f.window_offset, f.virtual_address, f.size, f.name + " (" + f.type_name + ")");
            }
        }

        if (ImGui::BeginPopupContextItem("field_ctx")) {
            if (f.is_pointer && f.pointer_target_va && *f.pointer_target_va != 0) {
                const std::string jump_lbl = std::format("Follow Pointer -> 0x{:X}", *f.pointer_target_va);
                if (ImGui::MenuItem(jump_lbl.c_str()) && on_pointer_activated_) {
                    on_pointer_activated_(*f.pointer_target_va);
                }
                if (!f.pointee_type_name.empty() && catalog.find(f.pointee_type_name) != nullptr) {
                    const std::string apply_lbl =
                        std::format("Apply {} @ 0x{:X}", f.pointee_type_name, *f.pointer_target_va);
                    if (ImGui::MenuItem(apply_lbl.c_str())) {
                        apply_structure_at(f.pointee_type_name, *f.pointer_target_va, false, 1);
                    }
                }
                ImGui::Separator();
            }
            if (ImGui::MenuItem("Copy Value")) {
                ImGui::SetClipboardText(f.decoded_value.c_str());
            }
            if (ImGui::MenuItem("Copy Address")) {
                const std::string addr_str = std::format("0x{:X}", f.virtual_address.value_or(f.address));
                ImGui::SetClipboardText(addr_str.c_str());
            }
            ImGui::EndPopup();
        }

        ImGui::TableSetColumnIndex(1);
        ImGui::TextDisabled("%s", f.type_name.c_str());

        ImGui::TableSetColumnIndex(2);
        if (f.virtual_address) {
            ImGui::Text("+0x%02" PRIX64 " (0x%" PRIX64 ")", f.relative_offset, *f.virtual_address);
        } else {
            ImGui::Text("+0x%02" PRIX64 " (off 0x%" PRIX64 ")", f.relative_offset, f.address);
        }

        ImGui::TableSetColumnIndex(3);
        ImGui::Text("%" PRIu64, f.size);

        ImGui::TableSetColumnIndex(4);
        if (f.availability == peelf::Availability::Unavailable) {
            ImGui::TextColored(ImVec4(0.95f, 0.42f, 0.42f, 1.0f), "%s", f.decoded_value.c_str());
        } else if (f.availability == peelf::Availability::Partial) {
            ImGui::TextColored(ImVec4(0.95f, 0.78f, 0.32f, 1.0f), "%s", f.decoded_value.c_str());
        } else if (f.is_pointer && f.pointer_target_va && *f.pointer_target_va != 0) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.45f, 0.82f, 1.0f, 1.0f));
            if (ImGui::Selectable(f.decoded_value.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick)) {
                if (on_pointer_activated_) {
                    on_pointer_activated_(*f.pointer_target_va);
                }
            }
            ImGui::PopStyleColor();
            if (ImGui::IsItemHovered()) {
                if (!f.pointee_type_name.empty() && catalog.find(f.pointee_type_name) != nullptr) {
                    ImGui::SetTooltip("Click to jump to 0x%" PRIX64 " | Right-click to apply %s",
                                      *f.pointer_target_va,
                                      f.pointee_type_name.c_str());
                } else {
                    ImGui::SetTooltip("Click to jump to 0x%" PRIX64, *f.pointer_target_va);
                }
            }
        } else {
            ImGui::TextUnformatted(f.decoded_value.c_str());
        }

        ImGui::TableSetColumnIndex(5);
        ImGui::TextDisabled("%s", f.raw_bytes_hex.c_str());

        if (has_children && open) {
            draw_field_rows(f.children, catalog, depth + 1);
            ImGui::TreePop();
        }

        ImGui::PopID();
    }
}

void StructureViewPanel::draw_contents() {
    if (last_synced_structure_revision_ != model_.structure_binding_revision()) {
        sync_custom_c_editor_from_model();
        dirty_ = true;
    }

    const std::span<const DataTypeRecord> extra_types =
        extra_types_provider_ ? extra_types_provider_() : std::span<const DataTypeRecord>{};

    if (!model_.has_file()) {
        if (ImGui::Button("Define / Import C Types...")) {
            show_custom_c_editor_ = !show_custom_c_editor_;
        }
        draw_custom_c_editor(extra_types);
        ImGui::TextDisabled("Open a PE/ELF binary or attach to a running process to apply structures.");
        return;
    }

    const StructureCatalog catalog = StructureCatalog::build_with_custom(
        model_.custom_types(), model_.debug_types(), extra_types, true);

    ensure_default_type_selected(catalog);

    if (model_.is_live_process() && use_file_offset_) {
        use_file_offset_ = false;
        dirty_ = true;
    }

    if (sync_with_selection_) {
        if (selection_.virtual_address && !use_file_offset_) {
            if (target_address_ != *selection_.virtual_address || last_synced_selection_is_off_) {
                target_address_ = *selection_.virtual_address;
                last_synced_selection_addr_ = target_address_;
                last_synced_selection_is_off_ = false;
                dirty_ = true;
            }
        } else if (selection_.file_offset && use_file_offset_) {
            if (target_address_ != *selection_.file_offset || !last_synced_selection_is_off_) {
                target_address_ = *selection_.file_offset;
                last_synced_selection_addr_ = target_address_;
                last_synced_selection_is_off_ = true;
                dirty_ = true;
            }
        }
    }

    if (last_eval_revision_ != model_.edit_revision()) {
        dirty_ = true;
    }

    // ---- Row 1: Structure Picker + Filter + Custom C Types Button ----
    ImGui::SetNextItemWidth(160.0f);
    if (ImGui::InputTextWithHint("##StructFilter", "Filter types...", type_filter_, sizeof(type_filter_))) {
        // Select first matching type automatically if current doesn't match
    }
    ImGui::SameLine();
    const std::string c_btn_label = model_.custom_types().empty()
        ? "Define / Import C Types..."
        : std::format("Define / Import C Types ({})...", model_.custom_types().size());
    const float right_buttons_w = ImGui::CalcTextSize(c_btn_label.c_str()).x + 115.0f;
    ImGui::SetNextItemWidth(std::max(160.0f, ImGui::GetContentRegionAvail().x - right_buttons_w));
    if (ImGui::BeginCombo("##StructCombo", selected_type_name_.c_str())) {
        for (const CatalogTypeEntry& entry : catalog.entries()) {
            if (type_filter_[0] != '\0' && !type_matches(entry.record, type_filter_)) {
                continue;
            }
            const bool is_sel = (entry.record.name == selected_type_name_);
            const std::string kind_tag = entry.record.is_enum
                ? "enum | "
                : (entry.record.is_union ? "union | " : "");
            const std::string item_lbl = std::format(
                "{}  [{}{} | {} B]",
                entry.record.name,
                kind_tag,
                to_string(entry.origin),
                entry.record.size);
            if (ImGui::Selectable(item_lbl.c_str(), is_sel)) {
                selected_type_name_ = entry.record.name;
                dirty_ = true;
            }
            if (is_sel) {
                ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    if (ImGui::Button("Refresh")) {
        dirty_ = true;
    }
    ImGui::SameLine();
    if (ImGui::Button(c_btn_label.c_str())) {
        show_custom_c_editor_ = !show_custom_c_editor_;
        if (show_custom_c_editor_) {
            focus_custom_c_editor_ = true;
        }
    }

    draw_custom_c_editor(extra_types);

    // ---- Row 2: Address / Mode / Count / Layout ----
    if (!model_.is_live_process()) {
        int addr_mode = use_file_offset_ ? 1 : 0;
        static constexpr std::array<const char*, 2> kAddrModeItems = {
            "Virtual Addr",
            "File Offset",
        };
        ImGui::SetNextItemWidth(110.0f);
        if (ImGui::Combo("##AddrMode",
                         &addr_mode,
                         kAddrModeItems.data(),
                         static_cast<int>(kAddrModeItems.size()))) {
            const bool want_off = (addr_mode == 1);
            if (want_off != use_file_offset_) {
                if (want_off) {
                    if (const auto off = model_.virtual_address_to_offset(target_address_)) {
                        target_address_ = *off;
                        use_file_offset_ = true;
                        addr_mode_warning_.clear();
                        dirty_ = true;
                    } else {
                        addr_mode_warning_ = std::format(
                            "VA 0x{:X} does not map to a file offset; keeping Virtual Addr mode.",
                            target_address_);
                    }
                } else {
                    if (const auto va = model_.offset_to_virtual_address(target_address_)) {
                        target_address_ = *va;
                        use_file_offset_ = false;
                        addr_mode_warning_.clear();
                        dirty_ = true;
                    } else {
                        addr_mode_warning_ = std::format(
                            "File offset 0x{:X} is outside mapped virtual sections; keeping File Offset mode.",
                            target_address_);
                    }
                }
            }
        }
        ImGui::SameLine();
    } else {
        ImGui::TextDisabled("Live VA:");
        ImGui::SameLine();
    }

    ImGui::SetNextItemWidth(150.0f);
    if (ImGui::InputScalar("##StructAddr",
                           ImGuiDataType_U64,
                           &target_address_,
                           nullptr,
                           nullptr,
                           "%" PRIX64,
                           ImGuiInputTextFlags_CharsHexadecimal)) {
        sync_with_selection_ = false;
        addr_mode_warning_.clear();
        dirty_ = true;
    }
    ImGui::SameLine();
    if (ImGui::Button("Use Selection")) {
        if (!use_file_offset_ && selection_.virtual_address) {
            target_address_ = *selection_.virtual_address;
            addr_mode_warning_.clear();
            dirty_ = true;
        } else if (use_file_offset_ && selection_.file_offset) {
            target_address_ = *selection_.file_offset;
            addr_mode_warning_.clear();
            dirty_ = true;
        }
    }
    ImGui::SameLine();
    if (ImGui::Checkbox("Sync", &sync_with_selection_) && sync_with_selection_) {
        addr_mode_warning_.clear();
        dirty_ = true;
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(72.0f);
    if (ImGui::InputInt("Count", &array_count_)) {
        array_count_ = std::clamp(array_count_, 1, 64);
        dirty_ = true;
    }

    if (!addr_mode_warning_.empty()) {
        ImGui::TextColored(ImVec4(0.95f, 0.72f, 0.25f, 1.0f), "%s", addr_mode_warning_.c_str());
    }

    // ---- Row 3: Target Layout Indicator + Pin Binding ----
    const peelf::TargetLayout base_layout = model_.target_layout();
    ImGui::TextDisabled("Target: %s %s",
                        base_layout.is_64bit() ? "64-bit" : "32-bit",
                        base_layout.endianness == peelf::Endianness::Big ? "Big-Endian" : "Little-Endian");
    ImGui::SameLine();
    static constexpr std::array<const char*, 3> kEndianOverrideItems = {
        "Endian: Auto",
        "Little",
        "Big",
    };
    ImGui::SetNextItemWidth(95.0f);
    if (ImGui::Combo("##EndianOvr",
                     &endian_override_,
                     kEndianOverrideItems.data(),
                     static_cast<int>(kEndianOverrideItems.size()))) {
        dirty_ = true;
    }
    ImGui::SameLine();
    static constexpr std::array<const char*, 3> kWidthOverrideItems = {
        "Ptr: Auto",
        "32-bit",
        "64-bit",
    };
    ImGui::SetNextItemWidth(95.0f);
    if (ImGui::Combo("##WidthOvr",
                     &width_override_,
                     kWidthOverrideItems.data(),
                     static_cast<int>(kWidthOverrideItems.size()))) {
        dirty_ = true;
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(130.0f);
    ImGui::InputTextWithHint("##PinLabel", "Optional label", binding_label_, sizeof(binding_label_));
    ImGui::SameLine();
    if (ImGui::Button("Pin Binding") && !selected_type_name_.empty()) {
        model_.add_applied_structure(AppliedStructureBinding{
            .address = target_address_,
            .is_file_offset = model_.is_live_process() ? false : use_file_offset_,
            .type_name = selected_type_name_,
            .count = static_cast<std::uint32_t>(std::clamp(array_count_, 1, 64)),
            .label = binding_label_,
        });
        binding_label_[0] = '\0';
    }

    // ---- Pinned Bindings List ----
    const auto pinned = model_.applied_structures();
    if (!pinned.empty() && ImGui::CollapsingHeader("Pinned Structure Bindings", ImGuiTreeNodeFlags_DefaultOpen)) {
        std::optional<std::size_t> to_remove;
        for (std::size_t i = 0; i < pinned.size(); ++i) {
            const AppliedStructureBinding& b = pinned[i];
            ImGui::PushID(static_cast<int>(i));
            const std::string desc = std::format(
                "{}{} @ {}0x{:X}{}",
                b.type_name,
                b.count > 1 ? std::format("[{}]", b.count) : std::string{},
                b.is_file_offset ? "off " : "",
                b.address,
                b.label.empty() ? std::string{} : (" (" + b.label + ")"));
            if (ImGui::SmallButton("Apply")) {
                apply_structure_at(b.type_name, b.address, b.is_file_offset, b.count);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("X")) {
                to_remove = i;
            }
            ImGui::SameLine();
            ImGui::TextUnformatted(desc.c_str());
            ImGui::PopID();
        }
        if (to_remove) {
            model_.remove_applied_structure(*to_remove);
        }
    }

    if (dirty_) {
        reevaluate(catalog);
    }

    if (!status_error_.empty()) {
        ImGui::TextColored(ImVec4(0.95f, 0.45f, 0.45f, 1.0f), "%s", status_error_.c_str());
        return;
    }
    if (!evaluated_) {
        return;
    }

    ImGui::Separator();
    ImGui::TextDisabled("%s (%s) | %" PRIu64 " bytes total | %s",
                        evaluated_->type_name.c_str(),
                        std::string(to_string(evaluated_->origin)).c_str(),
                        evaluated_->total_size,
                        evaluated_->availability == peelf::Availability::Available
                            ? "All bytes readable"
                            : (evaluated_->availability == peelf::Availability::Partial
                                   ? "Partial page / truncated read"
                                   : "Unreadable memory"));

    if (ImGui::BeginTable("StructEvalTable",
                          6,
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                              ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY,
                          ImVec2(0.0f, 0.0f))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthStretch, 0.24f);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthStretch, 0.16f);
        ImGui::TableSetupColumn("Offset / Addr", ImGuiTableColumnFlags_WidthStretch, 0.18f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 48.0f);
        ImGui::TableSetupColumn("Decoded Value", ImGuiTableColumnFlags_WidthStretch, 0.28f);
        ImGui::TableSetupColumn("Raw Bytes", ImGuiTableColumnFlags_WidthStretch, 0.14f);
        ImGui::TableHeadersRow();

        draw_field_rows(evaluated_->fields, catalog, 0);

        ImGui::EndTable();
    }
}

} // namespace viewer
