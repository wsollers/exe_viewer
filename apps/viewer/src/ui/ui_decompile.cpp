#include "ui_app.hpp"
#include <format>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

namespace viewer {
void UiApp::request_decompile() {
    show_decompiler_ = true;
    focus_decompiler_ = true;
    if (decompile_job_.valid()) return;
    const auto* image = model_.image();
    if (!image || !current_selection_.virtual_address) {
        decompiled_ = {DecompileStatus::NoFunction,"Decompiler","Select a mapped function first"}; return;
    }
    auto root = navigation_graph_root(*current_selection_.virtual_address);
    if (!root) { decompiled_ = {DecompileStatus::NoFunction,"Decompiler","No function selected"}; return; }
    const auto extent = discover_function_extent(*image,symbol_index_,*root,model_.bytes().size());
    if (!extent) { decompiled_ = {DecompileStatus::NoFunction,"Decompiler","Selection is not executable"}; return; }
    auto bytes = model_.read_effective_bytes(extent->file_offset,extent->size);
    if (!bytes) { decompiled_ = {DecompileStatus::Failed,"Decompiler",bytes.error().message}; return; }
    DecompileRequest request; request.address = extent->virtual_address; request.architecture = image->architecture();
    request.fallback_graph = build_function_cfg_call_graph(*bytes,extent->virtual_address,image->architecture(),image->endianness(),extent->file_offset,root->name,thumb_mode_,true);
    if (binary_ninja_) {
        auto snapshot = model_.read_effective_bytes(0,model_.bytes().size());
        if (!snapshot) { decompiled_ = {DecompileStatus::Failed,"Decompiler",snapshot.error().message}; return; }
        request.image_bytes = std::move(*snapshot);
    }
#ifdef _WIN32
    wchar_t executable[32768]{}; GetModuleFileNameW(nullptr,executable,32768);
    const auto bridge = std::filesystem::path(executable).parent_path()/"resources"/"bn_decompile.py";
#else
    const auto bridge = std::filesystem::canonical("/proc/self/exe").parent_path()/"resources"/"bn_decompile.py";
#endif
    decompile_stop_ = {}; const auto token = decompile_stop_.get_token();
    decompile_revision_ = model_.edit_revision(); decompile_generation_ = file_generation_;
    decompiled_ = {DecompileStatus::Ready,"Decompiler","Analyzing selected function..."};
    decompile_job_ = std::async(std::launch::async,[request=std::move(request),external=binary_ninja_,python=std::string(decompiler_python_),bridge,token]() {
        if (!external) return AnnotatedCodeDecompiler{}.decompile(request,token);
        BackendRunner runner; return BinaryNinjaDecompiler(python,bridge,runner).decompile(request,token);
    });
}
void UiApp::render_decompiler() {
    if (focus_decompiler_) { ImGui::SetNextWindowFocus(); focus_decompiler_ = false; }
    if (!ImGui::Begin("Decompiler",&show_decompiler_)) { ImGui::End(); return; }
    ImGui::Checkbox("Binary Ninja HLIL",&binary_ninja_);
    if (binary_ninja_) { ImGui::SetNextItemWidth(-1); ImGui::InputTextWithHint("##python", "Python executable with Binary Ninja API",decompiler_python_,sizeof(decompiler_python_)); }
    ImGui::BeginDisabled(decompile_job_.valid());
    if (ImGui::Button("Analyze selection (F5)")) request_decompile();
    ImGui::EndDisabled();
    if (decompile_job_.valid()) { ImGui::SameLine(); if (ImGui::Button("Cancel")) decompile_stop_.request_stop(); }
    ImGui::TextWrapped("%s",decompiled_.provider.c_str()); ImGui::TextWrapped("%s",decompiled_.diagnostic.c_str());
    if (!decompile_job_.valid() && decompiled_.status != DecompileStatus::Ready && binary_ninja_ && ImGui::Button("Show annotated code instead")) { binary_ninja_=false; request_decompile(); }
    const bool stale = decompile_revision_ != model_.edit_revision();
    if (stale) ImGui::TextWrapped("Bytes changed. Analyze again to refresh this snapshot.");
    std::optional<std::uint64_t> navigate;
    if (ImGui::BeginChild("decompiled_lines",ImVec2(0,0),false,ImGuiWindowFlags_HorizontalScrollbar)) {
        ImGuiListClipper clipper; clipper.Begin(static_cast<int>(decompiled_.lines.size()));
        while (clipper.Step()) for(int i=clipper.DisplayStart;i<clipper.DisplayEnd;++i) {
            const auto& line=decompiled_.lines[static_cast<std::size_t>(i)]; ImGui::PushID(i);
            if (line.address) {
                const auto label=std::format("{:X}  {}",*line.address,line.text);
                if (ImGui::Selectable(label.c_str(),current_selection_.virtual_address==line.address) && !stale) navigate=line.address;
            } else ImGui::TextUnformatted(line.text.c_str());
            ImGui::PopID();
        }
    }
    ImGui::EndChild(); ImGui::End();
    if (navigate) navigate_to_address(*navigate,PreferredView::Disassembly);
}
}
