#pragma once
#include "graph/call_graph.hpp"
#include <chrono>
#include <stop_token>
#include "symbols/data_types.hpp"

namespace viewer {
enum class DecompileStatus { Ready, Unavailable, Unsupported, NoFunction, Timeout, Cancelled, Failed };
struct CodeRange { std::uint64_t address{}, size{}; };
struct DecompiledLine {
    std::optional<std::uint64_t> address;
    std::string text;
    std::vector<CodeRange> ranges;
};
struct DecompiledUnit {
    DecompileStatus status = DecompileStatus::Failed;
    std::string provider, diagnostic;
    std::vector<DecompiledLine> lines;
    std::vector<DataTypeRecord> types;
};
struct DecompileRequest {
    std::uint64_t address{};
    peelf::Architecture architecture = peelf::Architecture::Unknown;
    std::vector<std::uint8_t> image_bytes;
    CallGraph fallback_graph;
    bool thumb = false;
    std::uint64_t function_size = 0; // Only authoritative symbol/runtime bounds.
    std::vector<SymbolRecord> symbols;
    std::vector<DataTypeRecord> types;
};
class IDecompiler {
public:
    virtual ~IDecompiler() = default;
    [[nodiscard]] virtual DecompiledUnit decompile(const DecompileRequest&, std::stop_token = {}) const = 0;
};
class AnnotatedCodeDecompiler final : public IDecompiler {
public:
    [[nodiscard]] DecompiledUnit decompile(const DecompileRequest&, std::stop_token = {}) const override;
};
struct BackendProcessResult { int exit_code = -1; bool timed_out = false, cancelled = false; };
class IBackendRunner {
public:
    virtual ~IBackendRunner() = default;
    virtual BackendProcessResult run(const std::filesystem::path& executable, const std::vector<std::string>& arguments,
        std::chrono::milliseconds timeout, std::stop_token) const = 0;
};
class BackendRunner final : public IBackendRunner {
public:
    BackendProcessResult run(const std::filesystem::path&, const std::vector<std::string>&,
        std::chrono::milliseconds, std::stop_token) const override;
};
class BinaryNinjaDecompiler final : public IDecompiler {
public:
    BinaryNinjaDecompiler(std::filesystem::path python, std::filesystem::path bridge, const IBackendRunner& runner)
        : python_(std::move(python)), bridge_(std::move(bridge)), runner_(runner) {}
    [[nodiscard]] DecompiledUnit decompile(const DecompileRequest&, std::stop_token = {}) const override;
private:
    std::filesystem::path python_, bridge_;
    const IBackendRunner& runner_;
};
[[nodiscard]] DecompiledUnit parse_decompiler_output(std::string_view);
[[nodiscard]] std::optional<SymbolRecord> containing_function(const peelf::IBinaryImage&, const SymbolIndex&,
    std::uint64_t address, const std::optional<SymbolRecord>& fallback = {});
[[nodiscard]] std::string encode_decompiler_symbols(const DecompileRequest&);
enum class DecompilerProvider {
    Ghidra = 0,
    BinaryNinja = 1,
    AnnotatedCode = 2,
    StructuredPseudoC = 3,
    RetDec = 4,
};
struct DecompilerSettings {
    DecompilerProvider provider = DecompilerProvider::Ghidra;
    std::filesystem::path ghidra_home;
    std::filesystem::path java = "java";
    std::filesystem::path python = "python";
    std::filesystem::path retdec = "retdec-decompiler";
    int timeout_seconds = 180;
};
[[nodiscard]] DecompilerSettings discover_decompilers(const std::filesystem::path& executable_directory);
[[nodiscard]] peelf::Result<DecompilerSettings> read_decompiler_settings(const std::filesystem::path&);
[[nodiscard]] peelf::Result<void> save_decompiler_settings(const std::filesystem::path&, const DecompilerSettings&);
class GhidraDecompiler final : public IDecompiler {
public:
    GhidraDecompiler(DecompilerSettings settings, std::filesystem::path scripts, const IBackendRunner& runner)
        : settings_(std::move(settings)), scripts_(std::move(scripts)), runner_(runner) {}
    [[nodiscard]] DecompiledUnit decompile(const DecompileRequest&, std::stop_token = {}) const override;
private:
    DecompilerSettings settings_;
    std::filesystem::path scripts_;
    const IBackendRunner& runner_;
};
}
