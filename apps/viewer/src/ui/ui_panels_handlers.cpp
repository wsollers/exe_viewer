#include "ui_panels.hpp"

#include <imgui.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cinttypes>
#include <cstdio>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace viewer {
namespace {

[[nodiscard]] bool icontains_hdl(std::string_view hay, std::string_view needle) noexcept {
    if (needle.empty()) {
        return true;
    }
    return std::search(hay.begin(), hay.end(), needle.begin(), needle.end(), [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
    }) != hay.end();
}

[[nodiscard]] bool matches_handler_category(peelf::HandlerCategory cat, int filter_idx) noexcept {
    switch (filter_idx) {
        case 1: return cat == peelf::HandlerCategory::SehChain32 ||
                       cat == peelf::HandlerCategory::SafeSehTable ||
                       cat == peelf::HandlerCategory::PeGuardEhContinuation;
        case 2: return cat == peelf::HandlerCategory::VehHandler ||
                       cat == peelf::HandlerCategory::VchHandler ||
                       cat == peelf::HandlerCategory::UnhandledExceptionFilter;
        case 3: return cat == peelf::HandlerCategory::PeUnwindException ||
                       cat == peelf::HandlerCategory::ElfEhFramePersonality;
        case 4: return cat == peelf::HandlerCategory::LinuxSignalDisposition;
        case 5: return cat == peelf::HandlerCategory::TlsCallback;
        case 6: return cat == peelf::HandlerCategory::CrtInitializer ||
                       cat == peelf::HandlerCategory::ElfInitFini;
        case 7: return cat == peelf::HandlerCategory::AtexitHandler;
        default: return true;
    }
}

[[nodiscard]] ImVec4 handler_avail_color(peelf::Availability a) noexcept {
    switch (a) {
        case peelf::Availability::Available:   return ImVec4(0.38f, 0.92f, 0.56f, 1.0f);
        case peelf::Availability::Partial:     return ImVec4(1.00f, 0.78f, 0.26f, 1.0f);
        case peelf::Availability::Unavailable: return ImVec4(0.95f, 0.48f, 0.45f, 1.0f);
    }
    return ImVec4(0.75f, 0.75f, 0.75f, 1.0f);
}

} // namespace

HandlersPanel::HandlersPanel(BinaryModel& model)
    : UiPanel("Handlers")
    , model_(model) {}

void HandlersPanel::draw_contents() {
    if (!model_.has_file()) {
        ImGui::TextDisabled("Open a PE/ELF binary or attach to a running process to inspect VEH, SEH, unwind, signal, TLS, CRT/init, and atexit handlers.");
        return;
    }

    const peelf::HandlersReport& rep = model_.handlers_report();
    const peelf::SubsystemStatus& primary_status =
        rep.static_handlers_status.is_usable() ? rep.static_handlers_status : rep.unwind_handlers_status;
    const std::string_view av = peelf::to_string(primary_status.availability);

    if (ImGui::SmallButton("Refresh")) {
        model_.refresh_runtime_and_handlers();
    }
    ImGui::SameLine();
    ImGui::TextColored(handler_avail_color(primary_status.availability),
                       "[%.*s] %s (%zu handler entries)",
                       static_cast<int>(av.size()),
                       av.data(),
                       primary_status.detail.c_str(),
                       rep.entries.size());

    static constexpr std::array<const char*, 8> kHandlerCategoryItems = {
        "All Categories",
        "SEH / SafeSEH / GuardEH",
        "VEH / VCH / Unhandled",
        "Unwind (.pdata / .eh_frame)",
        "Linux Signals",
        "TLS Callbacks",
        "Init / Fini / CRT",
        "atexit / __exit_funcs",
    };
    ImGui::SetNextItemWidth(190.0f);
    ImGui::Combo("##HandlerCat",
                 &category_filter_,
                 kHandlerCategoryItems.data(),
                 static_cast<int>(kHandlerCategoryItems.size()));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##HandlerFilter", "Filter symbol, handler name, address, or detail...", filter_buf_, sizeof(filter_buf_));

    const std::string_view filter(filter_buf_);
    std::vector<std::size_t> visible;
    visible.reserve(rep.entries.size());
    for (std::size_t i = 0; i < rep.entries.size(); ++i) {
        const peelf::HandlerEntry& h = rep.entries[i];
        if (!matches_handler_category(h.category, category_filter_)) {
            continue;
        }
        std::array<char, 32> habuf{};
        std::snprintf(habuf.data(), habuf.size(), "0x%" PRIX64, h.handler_address);
        if (!filter.empty() &&
            !icontains_hdl(h.name, filter) &&
            !icontains_hdl(h.symbol_name, filter) &&
            !icontains_hdl(h.detail, filter) &&
            !icontains_hdl(habuf.data(), filter)) {
            continue;
        }
        visible.push_back(i);
    }

    std::optional<std::pair<std::uint64_t, PreferredView>> pending_nav;
    if (ImGui::BeginTable("HandlersTable",
                          5,
                          ImGuiTableFlags_Borders |
                              ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_Resizable |
                              ImGuiTableFlags_ScrollY,
                          ImVec2(0.0f, rep.signals.empty() ? 0.0f : -150.0f))) {
        ImGui::TableSetupColumn("Category", ImGuiTableColumnFlags_WidthFixed, 132.0f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 155.0f);
        ImGui::TableSetupColumn("Handler VA", ImGuiTableColumnFlags_WidthFixed, 136.0f);
        ImGui::TableSetupColumn("Symbol", ImGuiTableColumnFlags_WidthStretch, 0.45f);
        ImGui::TableSetupColumn("Scope / Detail", ImGuiTableColumnFlags_WidthStretch, 0.55f);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        const int clipped_count = visible.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())
                                      ? std::numeric_limits<int>::max()
                                      : static_cast<int>(visible.size());
        ImGuiListClipper clipper;
        clipper.Begin(clipped_count);
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const peelf::HandlerEntry& h = rep.entries[visible[static_cast<std::size_t>(row)]];
                ImGui::TableNextRow();

                ImGui::TableNextColumn();
                const std::string_view csv = peelf::to_string(h.category);
                ImGui::TextDisabled("%.*s", static_cast<int>(csv.size()), csv.data());

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(h.name.c_str());

                ImGui::TableNextColumn();
                ImGui::PushID(row);
                if (h.handler_address != 0) {
                    std::array<char, 32> hbuf{};
                    std::snprintf(hbuf.data(), hbuf.size(), "0x%016" PRIX64, h.handler_address);
                    if (ImGui::Selectable(hbuf.data()) && on_address_activated_) {
                        pending_nav = std::pair{
                            h.handler_address,
                            (h.pointer_encoded && !h.pointer_decoded) ? PreferredView::Hex
                                                                      : PreferredView::Disassembly};
                    }
                } else {
                    ImGui::TextDisabled("-");
                }
                ImGui::PopID();

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(h.symbol_name.empty() ? "-" : h.symbol_name.c_str());

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(h.detail.empty() ? "-" : h.detail.c_str());
            }
        }
        ImGui::EndTable();
    }
    if (pending_nav.has_value() && on_address_activated_) {
        on_address_activated_(pending_nav->first, pending_nav->second);
    }

    if (!rep.signals.empty() && ImGui::CollapsingHeader("Linux Process Signal Dispositions (SigCgt / SigIgn / SigBlk)", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::BeginTable("LinuxSignalsTable",
                              4,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
            ImGui::TableSetupColumn("Signal", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Caught", ImGuiTableColumnFlags_WidthFixed, 70.0f);
            ImGui::TableSetupColumn("Ignored", ImGuiTableColumnFlags_WidthFixed, 70.0f);
            ImGui::TableSetupColumn("Blocked", ImGuiTableColumnFlags_WidthFixed, 70.0f);
            ImGui::TableHeadersRow();
            for (const peelf::SignalDispositionEntry& sig : rep.signals) {
                if (!sig.caught && !sig.ignored && !sig.blocked) {
                    continue;
                }
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text("%s (%d)", sig.signal_name.c_str(), sig.signal_number);
                ImGui::TableNextColumn();
                ImGui::TextColored(sig.caught ? ImVec4(0.42f, 0.92f, 0.58f, 1.0f) : ImVec4(0.5f, 0.5f, 0.5f, 1.0f),
                                   "%s",
                                   sig.caught ? "Yes" : "-");
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(sig.ignored ? "Yes" : "-");
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(sig.blocked ? "Yes" : "-");
            }
            ImGui::EndTable();
        }
    }
}

} // namespace viewer
