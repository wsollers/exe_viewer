#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <peelf/binary_image.hpp>
#include <peelf/error.hpp>
#include <peelf/forgiving.hpp>

namespace peelf {

enum class AssemblySyntax : std::uint8_t {
    Default = 0,
    Intel = 1,
    Att = 2,
};

struct AssembleRequest {
    Architecture architecture{Architecture::X86_64};
    Endianness endianness{Endianness::Little};
    bool is_64bit{true};
    bool thumb_mode{false};
    AssemblySyntax syntax{AssemblySyntax::Default};
    std::uint64_t base_address{0};
    std::string source_text{};
};

struct AssembledInstructionSpan {
    std::uint32_t line_number{1};
    std::uint64_t byte_offset{0};
    std::uint64_t byte_size{0};
    std::uint64_t virtual_address{0};
    std::string source_text{};
};

struct AssembleDiagnostic {
    std::uint32_t line_number{0};   // 1-based line number when known, 0 when global
    std::uint32_t column_number{0}; // 1-based column when known, 0 otherwise
    bool is_error{true};
    std::string message{};
    std::string line_text{};
};

struct AssembleOutput {
    std::string provider_name{};
    std::uint64_t base_address{0};
    std::vector<std::uint8_t> bytes{};
    std::vector<AssembledInstructionSpan> instruction_spans{};
    std::vector<AssembleDiagnostic> diagnostics{};
};

class IAssemblerProvider {
public:
    virtual ~IAssemblerProvider() = default;

    [[nodiscard]] virtual std::string_view name() const noexcept = 0;
    [[nodiscard]] virtual SubsystemStatus availability() const = 0;
    [[nodiscard]] virtual bool supports_target(Architecture architecture,
                                               Endianness endianness,
                                               bool is_64bit,
                                               bool thumb_mode = false) const noexcept = 0;
    [[nodiscard]] virtual Result<AssembleOutput> assemble(const AssembleRequest& request) const = 0;
};

/// In-process x86 (32-bit) and x86_64 (64-bit) fast-path assembler backed by AsmJit + AsmTK
/// when built with `PEELF_ENABLE_ASMTK=ON`. Supports labels, RIP-relative addressing, and
/// accurate relative branch displacements (`jmp`/`call`/`jcc`) relocated to `base_address`.
class AsmTkAssemblerProvider final : public IAssemblerProvider {
public:
    AsmTkAssemblerProvider() = default;

    [[nodiscard]] std::string_view name() const noexcept override { return "AsmTK"; }
    [[nodiscard]] SubsystemStatus availability() const override;
    [[nodiscard]] bool supports_target(Architecture architecture,
                                       Endianness endianness,
                                       bool is_64bit,
                                       bool thumb_mode = false) const noexcept override;
    [[nodiscard]] Result<AssembleOutput> assemble(const AssembleRequest& request) const override;
};

/// Optional external multi-architecture assembler adapter invoking `llvm-mc` safely via
/// `argv` process execution (never through a shell). Supports ARM, Thumb, AArch64, RISC-V 32/64,
/// PowerPC 32/64, MIPS 32/64, and x86/x86_64 fallback when `llvm-mc` is installed.
class LlvmMcAssemblerProvider final : public IAssemblerProvider {
public:
    explicit LlvmMcAssemblerProvider(std::filesystem::path explicit_llvm_mc_path = {});

    [[nodiscard]] std::string_view name() const noexcept override { return "llvm-mc"; }
    [[nodiscard]] SubsystemStatus availability() const override;
    [[nodiscard]] bool supports_target(Architecture architecture,
                                       Endianness endianness,
                                       bool is_64bit,
                                       bool thumb_mode = false) const noexcept override;
    [[nodiscard]] Result<AssembleOutput> assemble(const AssembleRequest& request) const override;

    [[nodiscard]] const std::filesystem::path& executable_path() const noexcept {
        return llvm_mc_path_;
    }

private:
    std::filesystem::path llvm_mc_path_{};
    SubsystemStatus status_{};
};

struct SubprocessResult {
    int exit_code{-1};
    bool launched{false};
    bool timed_out{false};
    std::string stdout_text{};
    std::string stderr_text{};
    std::string launch_error{};
};

/// Executes a child process directly via `argv` (never through a shell), multiplexing
/// `stdin_payload` concurrently with `stdout` and `stderr` drains and enforcing `timeout`
/// across the full child lifetime (terminating and reaping hung processes cleanly).
[[nodiscard]] SubprocessResult run_argv_process(
    const std::filesystem::path& exe_path,
    std::span<const std::string> args,
    std::string_view stdin_payload,
    std::chrono::milliseconds timeout = std::chrono::milliseconds{15000});

/// Deterministic target triple mapper for `llvm-mc` (exposed for unit testing).
[[nodiscard]] std::optional<std::string> llvm_mc_triple_for_target(
    Architecture architecture,
    Endianness endianness,
    bool is_64bit,
    bool thumb_mode = false);

/// Deterministic parser for `llvm-mc --show-encoding` stdout/stderr output.
/// Rejects unresolved symbolic fixups that cannot be represented as fixed byte patches
/// and extracts 1-based line/column diagnostics from `llvm-mc` stderr/stdout.
[[nodiscard]] Result<AssembleOutput> parse_llvm_mc_show_encoding_output(
    std::string_view stdout_text,
    std::string_view stderr_text,
    std::uint64_t base_address = 0,
    std::string_view provider_name = "llvm-mc");

class AssemblerRegistry {
public:
    AssemblerRegistry();
    explicit AssemblerRegistry(std::vector<std::shared_ptr<IAssemblerProvider>> providers);

    void register_provider(std::shared_ptr<IAssemblerProvider> provider);
    [[nodiscard]] std::span<const std::shared_ptr<IAssemblerProvider>> providers() const noexcept {
        return providers_;
    }

    [[nodiscard]] const IAssemblerProvider* select_provider(
        Architecture architecture,
        Endianness endianness,
        bool is_64bit,
        bool thumb_mode = false) const noexcept;

    [[nodiscard]] SubsystemStatus target_status(
        Architecture architecture,
        Endianness endianness,
        bool is_64bit,
        bool thumb_mode = false) const;

    [[nodiscard]] Result<AssembleOutput> assemble(const AssembleRequest& request) const;

private:
    std::vector<std::shared_ptr<IAssemblerProvider>> providers_{};
};

/// Convenience facade selecting the best available registered provider (`AsmTK` first for
/// x86/x86_64, `llvm-mc` for ARM/Thumb/AArch64/RISC-V/PowerPC/MIPS or x86 fallback).
[[nodiscard]] Result<AssembleOutput> assemble_instructions(
    Architecture architecture,
    Endianness endianness,
    bool is_64bit,
    bool thumb_mode,
    std::uint64_t base_va,
    std::string_view asm_text,
    AssemblySyntax syntax = AssemblySyntax::Default);

[[nodiscard]] const AssemblerRegistry& default_assembler_registry();

} // namespace peelf
