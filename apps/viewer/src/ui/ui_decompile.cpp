#include "ui_app.hpp"
#include <format>
#include <cstdio>
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
    auto root = navigation_graph_root(*current_selection_.virtual_address);
    if (!root) { decompiled_ = {DecompileStatus::NoFunction,"Decompiler","No function selected"}; return; }
    const auto extent = discover_function_extent(*image,symbol_index_,*root,model_.bytes().size());
    if (!extent) { decompiled_ = {DecompileStatus::NoFunction,"Decompiler","Selection is not executable"}; return; }
    auto bytes = model_.read_effective_bytes(extent->file_offset,extent->size);
    if (!bytes) { decompiled_ = {DecompileStatus::Failed,"Decompiler",bytes.error().message}; return; }
    DecompileRequest request; request.address = extent->virtual_address; request.architecture = image->architecture();
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
    const bool stale = decompile_revision_ != model_.edit_revision() || decompiler_thumb_ != thumb_mode_;
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
