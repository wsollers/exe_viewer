#pragma once

#include "decompile/decompiler.hpp"

#include <filesystem>

namespace viewer {

/// Built-in zero-dependency structured pseudo-C decompiler over Capstone + CallGraph CFG.
/// Works identically on static PE/ELF files and read-only live process modules across
/// x86, x86-64, ARM, ARM64, RISC-V, PowerPC, and MIPS, emitting function signatures,
/// register/stack local assignments, resolved symbol/import calls, structured if/else
/// and while loops (with goto fallback for irreducible edges), and exact address/CodeRange
/// mappings synced with Disassembly and Hex View.
class StructuredPseudoCDecompiler final : public IDecompiler {
public:
    [[nodiscard]] DecompiledUnit decompile(
        const DecompileRequest& request,
        std::stop_token stop = {}) const override;
};

/// Optional external RetDec CLI adapter (`retdec-decompiler` on PATH or configured path).
class RetDecDecompiler final : public IDecompiler {
public:
    RetDecDecompiler(std::filesystem::path executable, const IBackendRunner& runner, int timeout_seconds = 120)
        : executable_(std::move(executable)), runner_(runner), timeout_seconds_(timeout_seconds) {}

    [[nodiscard]] DecompiledUnit decompile(
        const DecompileRequest& request,
        std::stop_token stop = {}) const override;

    [[nodiscard]] static std::filesystem::path find_on_path(
        std::filesystem::path preferred = "retdec-decompiler");

private:
    std::filesystem::path executable_;
    const IBackendRunner& runner_;
    int timeout_seconds_{120};
};

}  // namespace viewer
