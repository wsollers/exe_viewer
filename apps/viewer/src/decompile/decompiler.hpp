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
#include <unordered_map>
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
    std::optional<std::uint64_t> address{};
    std::string text{};
    std::vector<CodeRange> ranges{};
};
struct DecompiledUnit {
    DecompileStatus status = DecompileStatus::Failed;
    std::string provider{}, diagnostic{};
    std::vector<DecompiledLine> lines{};
    std::vector<DataTypeRecord> types{};
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
    std::optional<DecompilerFunctionOverride> function_override{};
};

[[nodiscard]] std::string rewrite_decompiler_c_tokens(
    std::string_view code,
    const std::unordered_map<std::string, std::string>& rename_map,
    bool& in_block_comment);

[[nodiscard]] std::string rewrite_decompiler_c_tokens(
    std::string_view code,
    const std::unordered_map<std::string, std::string>& rename_map);

void apply_decompiler_overrides(
    DecompiledUnit& unit,
    const DecompilerFunctionOverride& override_spec);

[[nodiscard]] std::string compute_decompiler_override_digest(
    const std::optional<DecompilerFunctionOverride>& override_spec);
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
enum class DecompilerProvider {
    Ghidra = 0,
    BinaryNinja = 1,
    AnnotatedCode = 2,
    StructuredPseudoC = 3,
    RetDec = 4,
};

enum class BinaryNinjaEdition : std::uint8_t {
    Unknown = 0,
    Free,
    Personal,
    Commercial,
    Ultimate,
    Headless,
};

[[nodiscard]] constexpr std::string_view to_string(BinaryNinjaEdition edition) noexcept {
    switch (edition) {
        case BinaryNinjaEdition::Unknown:    return "Unknown";
        case BinaryNinjaEdition::Free:       return "Free";
        case BinaryNinjaEdition::Personal:   return "Personal";
        case BinaryNinjaEdition::Commercial: return "Commercial";
        case BinaryNinjaEdition::Ultimate:   return "Ultimate";
        case BinaryNinjaEdition::Headless:   return "Headless";
    }
    return "Unknown";
}

struct BinaryNinjaCapabilityStatus {
    bool install_found = false;
    bool python_api_available = false;
    bool headless_supported = false;
    BinaryNinjaEdition edition = BinaryNinjaEdition::Unknown;
    std::string version{};
    std::filesystem::path install_directory{};
    std::filesystem::path python_api_directory{};
    std::filesystem::path settings_source{};
    std::vector<peelf::Architecture> supported_architectures{};
    std::string status_summary{};
};

struct BinaryNinjaDiscoveryEnv {
    bool include_system_defaults = true;
    std::optional<std::filesystem::path> bn_install_dir{};
    std::optional<std::filesystem::path> binaryninja_home{};
    std::vector<std::filesystem::path> user_settings_directories{};
    std::vector<std::filesystem::path> standard_install_directories{};
    std::optional<std::string> path_env{};
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
    std::filesystem::path binary_ninja_home{};
};

class BinaryNinjaDecompiler final : public IDecompiler {
public:
    BinaryNinjaDecompiler(std::filesystem::path python,
                          std::filesystem::path bridge,
                          const IBackendRunner& runner,
                          std::filesystem::path binary_ninja_home = {},
                          int timeout_seconds = 60,
                          std::optional<BinaryNinjaCapabilityStatus> capabilities = std::nullopt)
        : python_(std::move(python))
        , bridge_(std::move(bridge))
        , binary_ninja_home_(std::move(binary_ninja_home))
        , timeout_seconds_(timeout_seconds)
        , capabilities_(std::move(capabilities))
        , runner_(runner) {}

    BinaryNinjaDecompiler(const DecompilerSettings& settings,
                          std::filesystem::path bridge,
                          const IBackendRunner& runner,
                          std::optional<BinaryNinjaCapabilityStatus> capabilities = std::nullopt)
        : python_(settings.python)
        , bridge_(std::move(bridge))
        , binary_ninja_home_(settings.binary_ninja_home)
        , timeout_seconds_(settings.timeout_seconds)
        , capabilities_(std::move(capabilities))
        , runner_(runner) {}

    [[nodiscard]] DecompiledUnit decompile(const DecompileRequest&, std::stop_token = {}) const override;
private:
    std::filesystem::path python_;
    std::filesystem::path bridge_;
    std::filesystem::path binary_ninja_home_;
    int timeout_seconds_ = 60;
    std::optional<BinaryNinjaCapabilityStatus> capabilities_;
    const IBackendRunner& runner_;
};

struct DecompileCacheKey {
    std::string binary_sha256;
    std::uint64_t patch_revision = 0;
    std::uint64_t symbol_revision = 0;
    std::string symbols_sha256;
    std::string function_override_sha256;
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

[[nodiscard]] DecompiledUnit parse_decompiler_output(std::string_view);
[[nodiscard]] std::optional<SymbolRecord> containing_function(const peelf::IBinaryImage&, const SymbolIndex&,
    std::uint64_t address, const std::optional<SymbolRecord>& fallback = {});
[[nodiscard]] std::string encode_decompiler_symbols(const DecompileRequest&);
[[nodiscard]] std::string compute_decompiler_symbols_digest(
    std::span<const SymbolRecord> symbols,
    std::span<const DataTypeRecord> types);

[[nodiscard]] std::filesystem::path safe_decompiler_scratch_directory();
[[nodiscard]] std::filesystem::path default_ghidra_cache_directory();
void clear_ghidra_workspace_cache(const std::filesystem::path& cache_root);

[[nodiscard]] DecompilerSettings discover_decompilers(const std::filesystem::path& executable_directory);
[[nodiscard]] BinaryNinjaCapabilityStatus discover_binary_ninja(
    const DecompilerSettings& settings,
    const BinaryNinjaDiscoveryEnv& env = {});
[[nodiscard]] BinaryNinjaCapabilityStatus probe_binary_ninja_capabilities(
    const DecompilerSettings& settings,
    const std::filesystem::path& bridge_script,
    const IBackendRunner& runner,
    const BinaryNinjaDiscoveryEnv& env = {},
    std::stop_token stop = {});
[[nodiscard]] peelf::Result<void> check_binary_ninja_architecture_support(
    const BinaryNinjaCapabilityStatus& caps,
    peelf::Architecture arch);
[[nodiscard]] peelf::Result<void> check_binary_ninja_headless_support(
    const BinaryNinjaCapabilityStatus& caps,
    peelf::Architecture arch);
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
