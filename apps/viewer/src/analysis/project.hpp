#pragma once
#include "analysis/reference_index.hpp"
#include "model/binary_model.hpp"
#include "navigation/viewer_navigation.hpp"

namespace viewer {
struct AnalysisProject {
    std::string source;
    std::uint64_t source_size{}, fingerprint{};
    std::vector<peelf::PatchInterval> patches;
    std::map<std::uint64_t, Annotation> annotations;
    std::vector<DebugSymbol> symbols;
    std::vector<ViewerSelection> history;
    std::size_t cursor{};
    std::string layout;
    bool thumb = false;
};
[[nodiscard]] std::uint64_t binary_fingerprint(std::span<const std::uint8_t>) noexcept;
[[nodiscard]] std::string encode_project(const AnalysisProject&);
[[nodiscard]] peelf::Result<AnalysisProject> decode_project(std::string_view);
[[nodiscard]] peelf::Result<void> restore_project_patches(BinaryModel&, const AnalysisProject&);
[[nodiscard]] peelf::Result<std::string> read_project_file(const std::filesystem::path&);
[[nodiscard]] peelf::Result<void> write_analysis_file(const std::filesystem::path&, std::string_view);
}
