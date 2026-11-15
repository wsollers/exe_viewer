#pragma once
#include "model/binary_model.hpp"
#include "graph/call_graph.hpp"

namespace viewer {
struct PatchPreview {
    std::uint64_t offset{}, revision{};
    std::vector<std::uint8_t> replacement;
    CallGraph before, after;
    std::string boundary;
};
[[nodiscard]] peelf::Result<PatchPreview> preview_patch(const BinaryModel&, const SymbolIndex&,
    std::uint64_t offset, std::span<const std::uint8_t> replacement, bool thumb = false);
[[nodiscard]] peelf::Result<void> apply_preview(BinaryModel&, const PatchPreview&);
[[nodiscard]] std::string patch_report(const BinaryModel&);
}
