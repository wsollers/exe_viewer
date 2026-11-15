#pragma once
#include "graph/call_graph.hpp"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <list>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include "symbols/data_types.hpp"

namespace viewer {
enum class DecompileStatus { Ready, Unavailable, Unsupported, NoFunction, Timeout, Cancelled, Failed };

enum class DecompileCacheSource : std::uint8_t {
    FreshAnalysis = 0,
    ReusedWorkspace = 1,
    MemoryCacheHit = 2,
};

[[nodiscard]] constexpr std::string_view to_string(DecompileCacheSource source) noexcept {
    switch (source) {
        case DecompileCacheSource::FreshAnalysis:   return "Fresh analysis";
        case DecompileCacheSource::ReusedWorkspace: return "Reused Ghidra workspace";
        case DecompileCacheSource::MemoryCacheHit:  return "Cached result";
    }
    return "Fresh analysis";
}

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
    DecompileCacheSource cache_source = DecompileCacheSource::FreshAnalysis;
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
    peelf::Endianness endianness = peelf::Endianness::Little;
    std::string binary_sha256;
    std::uint64_t patch_revision = 0;
    std::uint64_t symbol_revision = 0;
    bool force_reanalyze = false;
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
[[nodiscard]] std::string compute_decompiler_symbols_digest(
    std::span<const SymbolRecord> symbols,
    std::span<const DataTypeRecord> types);

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
    std::filesystem::path cache_directory;
    std::size_t max_cached_workspaces = 3;
    bool reuse_analysis = true;
};

struct DecompileCacheKey {
    std::string binary_sha256;
    std::uint64_t patch_revision = 0;
    std::uint64_t symbol_revision = 0;
    std::string symbols_sha256;
    DecompilerProvider provider = DecompilerProvider::Ghidra;
    std::string settings_fingerprint;
    peelf::Architecture architecture = peelf::Architecture::Unknown;
    peelf::Endianness endianness = peelf::Endianness::Little;
    bool thumb = false;
    std::uint64_t function_address = 0;
    std::uint64_t function_size = 0;

    auto operator<=>(const DecompileCacheKey&) const = default;
};

[[nodiscard]] std::string compute_decompiler_settings_fingerprint(const DecompilerSettings& settings);
[[nodiscard]] DecompileCacheKey make_decompile_cache_key(
    const DecompileRequest& request,
    const DecompilerSettings& settings);

class DecompileCache {
public:
    explicit DecompileCache(std::size_t max_entries = 128) noexcept
        : max_entries_(max_entries == 0 ? 1 : max_entries) {}

    [[nodiscard]] std::optional<DecompiledUnit> get(const DecompileCacheKey& key) const;
    void put(const DecompileCacheKey& key, DecompiledUnit unit);
    void invalidate_function(std::string_view binary_sha256, std::uint64_t function_address);
    void invalidate_binary(std::string_view binary_sha256);
    void clear();
    [[nodiscard]] std::size_t size() const;

private:
    struct Entry {
        DecompileCacheKey key;
        DecompiledUnit unit;
    };

    std::size_t max_entries_ = 128;
    mutable std::mutex mutex_;
    mutable std::list<Entry> lru_;
    mutable std::map<DecompileCacheKey, std::list<Entry>::iterator> index_;
};

[[nodiscard]] std::filesystem::path default_ghidra_cache_directory();
void clear_ghidra_workspace_cache(const std::filesystem::path& cache_root);

[[nodiscard]] DecompilerSettings discover_decompilers(const std::filesystem::path& executable_directory);
[[nodiscard]] peelf::Result<DecompilerSettings> read_decompiler_settings(const std::filesystem::path&);
[[nodiscard]] peelf::Result<void> save_decompiler_settings(const std::filesystem::path&, const DecompilerSettings&);
class GhidraDecompiler final : public IDecompiler {
public:
    GhidraDecompiler(DecompilerSettings settings, std::filesystem::path scripts, const IBackendRunner& runner)
        : settings_(std::move(settings)), scripts_(std::move(scripts)), runner_(runner) {}
    [[nodiscard]] DecompiledUnit decompile(const DecompileRequest&, std::stop_token = {}) const override;
    [[nodiscard]] std::filesystem::path effective_cache_directory() const;
    void clear_cached_workspaces() const;
private:
    DecompilerSettings settings_;
    std::filesystem::path scripts_;
    const IBackendRunner& runner_;
};
}
