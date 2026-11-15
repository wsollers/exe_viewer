#include "ui_app.hpp"
#include <format>
#include <cstdio>
#include <algorithm>
#include <limits>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

namespace viewer {
void UiApp::initialize_decompiler() {
#ifdef _WIN32
    wchar_t executable[32768]{}; GetModuleFileNameW(nullptr, executable, 32768);
    decompiler_directory_ = std::filesystem::path(executable).parent_path();
#else
    std::error_code ec;
    decompiler_directory_ = std::filesystem::canonical("/proc/self/exe", ec).parent_path();
#endif
    auto settings = discover_decompilers(decompiler_directory_);
    const auto path = decompiler_directory_ / "decompiler.ini";
    if (std::filesystem::exists(path)) {
        auto saved = read_decompiler_settings(path);
        if (saved) settings = *saved;
        else decompiler_settings_status_ = saved.error().message;
    }
    decompiler_provider_ = static_cast<int>(settings.provider);
    decompiler_timeout_ = settings.timeout_seconds;
    std::snprintf(ghidra_home_, sizeof(ghidra_home_), "%s", settings.ghidra_home.string().c_str());
    std::snprintf(decompiler_java_, sizeof(decompiler_java_), "%s", settings.java.string().c_str());
    std::snprintf(decompiler_python_, sizeof(decompiler_python_), "%s", settings.python.string().c_str());
}
void UiApp::request_decompile() {
    show_decompiler_ = true;
    focus_decompiler_ = true;
    if (decompile_job_.valid()) return;
    const auto* image = model_.image();
    if (!image || !current_selection_.virtual_address) {
        decompiled_ = {DecompileStatus::NoFunction,"Decompiler","Select a mapped function first"}; return;
    }
    auto root = containing_function(*image, symbol_index_, *current_selection_.virtual_address,
        navigation_graph_root(*current_selection_.virtual_address));
    if (!root) { decompiled_ = {DecompileStatus::NoFunction,"Decompiler","No function selected"}; return; }
    const auto extent = discover_function_extent(*image,symbol_index_,*root,model_.bytes().size());
    if (!extent) { decompiled_ = {DecompileStatus::NoFunction,"Decompiler","Selection is not executable"}; return; }
    auto bytes = model_.read_effective_bytes(extent->file_offset,extent->size);
    if (!bytes) { decompiled_ = {DecompileStatus::Failed,"Decompiler",bytes.error().message}; return; }
    DecompileRequest request; request.address = extent->virtual_address; request.architecture = image->architecture();
    if (const auto full = discover_function_extent(*image,symbol_index_,*root,model_.bytes().size(),std::numeric_limits<std::uint64_t>::max());
        full && (full->source == FunctionExtentSource::Symbol || full->source == FunctionExtentSource::RuntimeMetadata))
        request.function_size = full->size;
    for (auto symbol : symbol_index_.records()) {
        symbol.function = symbol_has_code(*image,symbol);
        if (symbol.virtual_address) if (const auto* note = annotations_.find(*symbol.virtual_address); note && !note->name.empty()) {
            symbol.name = note->name; symbol.source = SymbolSource::DebugSymbol;
        }
        request.symbols.push_back(std::move(symbol));
    }
    request.types = debug_types_;
    decompiled_root_ = root; selected_code_ranges_.clear(); selected_code_address_.reset();
    request.thumb = image->architecture() == peelf::Architecture::ARM && thumb_mode_;
    request.fallback_graph = build_function_cfg_call_graph(*bytes,extent->virtual_address,image->architecture(),image->endianness(),extent->file_offset,root->name,thumb_mode_,true);
    if (decompiler_provider_ != 2) {
        auto snapshot = model_.read_effective_bytes(0,model_.bytes().size());
        if (!snapshot) { decompiled_ = {DecompileStatus::Failed,"Decompiler",snapshot.error().message}; return; }
        request.image_bytes = std::move(*snapshot);
    }
    const auto resources = decompiler_directory_ / "resources";
    DecompilerSettings settings{static_cast<DecompilerProvider>(decompiler_provider_), ghidra_home_, decompiler_java_, decompiler_python_, decompiler_timeout_};
    decompile_stop_ = {}; const auto token = decompile_stop_.get_token();
    decompile_revision_ = model_.edit_revision(); decompile_generation_ = file_generation_;
    decompiler_thumb_ = thumb_mode_;
    decompile_annotation_revision_ = annotations_.revision(); decompile_symbol_revision_ = symbol_revision_;
    decompiled_ = {DecompileStatus::Ready,"Decompiler","Analyzing selected function..."};
    decompile_job_ = std::async(std::launch::async,[request=std::move(request),settings,resources,token]() {
        BackendRunner runner;
        switch (settings.provider) {
        case DecompilerProvider::Ghidra: return GhidraDecompiler(settings, resources, runner).decompile(request,token);
        case DecompilerProvider::BinaryNinja: return BinaryNinjaDecompiler(settings.python,resources/"bn_decompile.py",runner).decompile(request,token);
        default: return AnnotatedCodeDecompiler{}.decompile(request,token);
        }
    });
}
void UiApp::render_decompiler() {
    if (focus_decompiler_) { ImGui::SetNextWindowFocus(); focus_decompiler_ = false; }
    if (!ImGui::Begin("Decompiler",&show_decompiler_)) { ImGui::End(); return; }
    ImGui::BeginDisabled(decompile_job_.valid());
    ImGui::SetNextItemWidth(-1);
    ImGui::Combo("##provider", &decompiler_provider_, "Ghidra (default)\0Binary Ninja HLIL\0Annotated assembly\0");
    if (ImGui::CollapsingHeader("Backend settings")) {
        if (decompiler_provider_ == 0) {
            ImGui::TextUnformatted("Ghidra installation folder"); ImGui::SetNextItemWidth(-1);
            ImGui::InputText("##ghidra", ghidra_home_, sizeof(ghidra_home_));
            ImGui::TextUnformatted("Java executable (JDK 25 for Ghidra 12.2)"); ImGui::SetNextItemWidth(-1);
            ImGui::InputText("##java", decompiler_java_, sizeof(decompiler_java_));
            ImGui::InputInt("Timeout (seconds)", &decompiler_timeout_);
        } else if (decompiler_provider_ == 1) {
            ImGui::TextWrapped("Headless API requires Binary Ninja Commercial or above. Personal is not supported by this adapter.");
            ImGui::SetNextItemWidth(-1); ImGui::InputTextWithHint("##python", "Python with Binary Ninja API",decompiler_python_,sizeof(decompiler_python_));
        }
        if (ImGui::Button("Save settings")) {
            const DecompilerSettings settings{static_cast<DecompilerProvider>(decompiler_provider_), ghidra_home_, decompiler_java_, decompiler_python_, decompiler_timeout_};
            if (decompiler_timeout_ < 10 || decompiler_timeout_ > 3600) decompiler_settings_status_ = "Timeout must be 10 to 3600 seconds.";
            else {
                const auto result = save_decompiler_settings(decompiler_directory_/"decompiler.ini", settings);
                decompiler_settings_status_ = result ? "Settings saved." : result.error().message;
            }
        }
        ImGui::TextWrapped("%s", decompiler_settings_status_.c_str());
    }
    ImGui::EndDisabled();
    ImGui::BeginDisabled(decompile_job_.valid());
    if (ImGui::Button("Analyze selection (F5)")) request_decompile();
    ImGui::EndDisabled();
    if (decompile_job_.valid()) { ImGui::SameLine(); if (ImGui::Button("Cancel")) decompile_stop_.request_stop(); }
    ImGui::TextWrapped("%s",decompiled_.provider.c_str()); ImGui::TextWrapped("%s",decompiled_.diagnostic.c_str());
    if (!decompile_job_.valid() && decompiled_.status != DecompileStatus::Ready && decompiler_provider_ != 2 && ImGui::Button("Show annotated code instead")) { decompiler_provider_=2; request_decompile(); }
    const bool stale = decompile_revision_ != model_.edit_revision() || decompiler_thumb_ != thumb_mode_ ||
        decompile_annotation_revision_ != annotations_.revision() || decompile_symbol_revision_ != symbol_revision_;
    if (stale) ImGui::TextWrapped("Bytes or symbols changed. Analyze again to refresh this snapshot.");
    std::optional<std::size_t> navigate;
    if (code_font_) ImGui::PushFont(code_font_);
    if (ImGui::BeginTable("decompiled_lines",2,ImGuiTableFlags_ScrollY|ImGuiTableFlags_ScrollX|ImGuiTableFlags_RowBg|ImGuiTableFlags_BordersInnerV|ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Address",ImGuiTableColumnFlags_WidthFixed,ImGui::CalcTextSize("0000000000000000").x+16);
        ImGui::TableSetupColumn("Code",ImGuiTableColumnFlags_WidthFixed,ImGui::GetFontSize()*80);
        ImGui::TableSetupScrollFreeze(1,1); ImGui::TableHeadersRow();
        ImGuiListClipper clipper; clipper.Begin(static_cast<int>(decompiled_.lines.size()));
        while (clipper.Step()) for(int i=clipper.DisplayStart;i<clipper.DisplayEnd;++i) {
            const auto& line=decompiled_.lines[static_cast<std::size_t>(i)]; ImGui::PushID(i);
            ImGui::TableNextRow(); ImGui::TableSetColumnIndex(0);
            if (line.address) {
                const auto label=std::format("{:016X}",*line.address);
                bool selected=current_selection_.virtual_address==line.address;
                for (const auto& range : line.ranges) if (current_selection_.virtual_address && *current_selection_.virtual_address>=range.address &&
                    *current_selection_.virtual_address-range.address<range.size) selected=true;
                if (ImGui::Selectable(label.c_str(),selected,ImGuiSelectableFlags_SpanAllColumns) && !stale) navigate=static_cast<std::size_t>(i);
            } else ImGui::TextDisabled("—");
            ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(line.text.c_str());
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    if (code_font_) ImGui::PopFont();
    ImGui::End();
    if (navigate) select_decompiled_line(*navigate);
}
void UiApp::select_decompiled_line(std::size_t index) {
    const auto& line=decompiled_.lines.at(index);
    if (!line.address || !model_.image()) return;
    current_selection_.graph_root=decompiled_root_;
    navigate_to_address(*line.address,PreferredView::Graph);
    if (current_selection_.virtual_address != line.address) return;
    current_selection_.graph_root=decompiled_root_;
    selected_code_ranges_=line.ranges;
    if (selected_code_ranges_.empty()) {
        auto instruction=std::ranges::find(current_instructions_,*line.address,&Instruction::address);
        selected_code_ranges_.push_back({*line.address,instruction==current_instructions_.end() ? 1 : instruction->bytes.size()});
    }
    std::vector<ByteRange> bytes;
    for (const auto& range : selected_code_ranges_) {
        const auto offset=model_.image()->virtual_address_to_file_offset(range.address);
        if (!offset || !range.size || *offset>=model_.bytes().size() || range.size>model_.bytes().size()-*offset) continue;
        const auto last=model_.image()->virtual_address_to_file_offset(range.address+range.size-1);
        if (!last || *last!=*offset+range.size-1) continue;
        bytes.push_back({static_cast<std::size_t>(*offset),static_cast<std::size_t>(range.size)});
    }
    if (!bytes.empty()) {
        hex_panel_.navigate_to_ranges(bytes); hex_panel_.set_visible(true);
        current_selection_.size=bytes.front().size; last_navigation_selection_=current_selection_;
    }
    selected_code_address_=line.address;
    if (decompiled_root_ && (!active_graph_root_ || active_graph_root_->virtual_address!=decompiled_root_->virtual_address)) {
        pending_call_graph_root_=decompiled_root_; pending_call_graph_delay_frames_=0;
    }
}
void UiApp::render_data_types() {
    if (!ImGui::Begin("Data Structures",&show_data_types_)) { ImGui::End(); return; }
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##type_search","Search structures, members, types, or data symbols...",data_type_filter_,sizeof(data_type_filter_));
    if (ImGui::BeginTabBar("data_views")) {
        if (ImGui::BeginTabItem("Structures")) {
            if (debug_types_.empty() && decompiled_.types.empty())
                ImGui::TextWrapped("No structure definitions loaded. Load a PDB with type information or decompile an image containing debug types. Symbol names alone do not describe member layouts.");
            auto draw=[&](const DataTypeRecord& type) {
                if (!type_matches(type,data_type_filter_)) return;
                ImGui::PushID(type.name.c_str());
                const auto label=std::format("{} {} ({} bytes)",type.is_union ? "union" : "struct",type.name,type.size);
                if (ImGui::TreeNodeEx("##type",ImGuiTreeNodeFlags_SpanAvailWidth,"%s",label.c_str())) {
                    if (ImGui::BeginTable("members",4,ImGuiTableFlags_RowBg|ImGuiTableFlags_BordersInnerV|ImGuiTableFlags_Resizable)) {
                        for (const auto* name : {"Offset","Size","Member","Type"}) ImGui::TableSetupColumn(name);
                        ImGui::TableHeadersRow();
                        for (const auto& member : type.members) {
                            ImGui::TableNextRow(); ImGui::TableSetColumnIndex(0); ImGui::Text("0x%llX",static_cast<unsigned long long>(member.offset));
                            ImGui::TableSetColumnIndex(1); ImGui::Text("%llu",static_cast<unsigned long long>(member.size));
                            ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(member.name.c_str());
                            ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(member.type.c_str());
                        }
                        ImGui::EndTable();
                    }
                    ImGui::TreePop();
                }
                ImGui::PopID();
            };
            for (const auto& type : debug_types_) draw(type);
            for (const auto& type : decompiled_.types)
                if (std::ranges::none_of(debug_types_,[&](const auto& known){return known.name==type.name;})) draw(type);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Data symbols")) {
            if (model_.image() && ImGui::BeginTable("data_symbols",3,ImGuiTableFlags_RowBg|ImGuiTableFlags_Resizable|ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("Name"); ImGui::TableSetupColumn("Address"); ImGui::TableSetupColumn("Size"); ImGui::TableHeadersRow();
                for (const auto& symbol : symbol_index_.records()) {
                    if (!symbol.virtual_address || symbol_has_code(*model_.image(),symbol) || !symbol_name_matches(symbol.name,data_type_filter_)) continue;
                    ImGui::PushID(&symbol); ImGui::TableNextRow(); ImGui::TableSetColumnIndex(0);
                    if (ImGui::Selectable(symbol.name.c_str(),current_selection_.virtual_address==symbol.virtual_address,ImGuiSelectableFlags_SpanAllColumns)) {
                        navigate_to_address(*symbol.virtual_address,PreferredView::Hex);
                        if (symbol.file_offset && symbol.size) hex_panel_.navigate_to_range(*symbol.file_offset,symbol.size);
                    }
                    ImGui::TableSetColumnIndex(1); ImGui::Text("%016llX",static_cast<unsigned long long>(*symbol.virtual_address));
                    ImGui::TableSetColumnIndex(2); ImGui::Text("%llu",static_cast<unsigned long long>(symbol.size)); ImGui::PopID();
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}
}
