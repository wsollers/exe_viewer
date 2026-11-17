#pragma once

#include <peelf/binary_image.hpp>
#include <peelf/capability_matrix.hpp>
#include <peelf/crash_dump.hpp>
#include <peelf/error.hpp>
#include <peelf/patching.hpp>
#include <peelf/process.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

struct lua_State;

namespace peelf {

/// RAII custom deleter closing an embedded `lua_State*` via `lua_close`.
struct LuaStateDeleter {
    void operator()(lua_State* state) const noexcept;
};

using UniqueLuaState = std::unique_ptr<lua_State, LuaStateDeleter>;

/// Creates a standalone default-allocated `lua_State` owned immediately by `UniqueLuaState`.
[[nodiscard]] UniqueLuaState make_unique_lua_state() noexcept;

/// Deterministic resource quotas enforced on every untrusted Lua 5.4 script execution.
struct ScriptLimits {
    std::size_t max_memory_bytes{16u * 1024u * 1024u};
    std::uint64_t max_instructions{1'000'000u};
    std::chrono::milliseconds wall_clock_timeout{5000};
    std::size_t max_output_bytes{1u * 1024u * 1024u};
};

/// Classification of script execution outcomes and quota/sandbox terminations.
enum class ScriptErrorKind : std::uint8_t {
    None = 0,
    InvalidConfiguration,
    SyntaxOrLoadError,
    RuntimeError,
    MemoryLimitExceeded,
    InstructionLimitExceeded,
    WallClockTimeout,
    OutputLimitExceeded,
    Cancelled,
    CommitFailed,
};

[[nodiscard]] constexpr std::string_view to_string(ScriptErrorKind kind) noexcept {
    switch (kind) {
        case ScriptErrorKind::None:                     return "None";
        case ScriptErrorKind::InvalidConfiguration:     return "InvalidConfiguration";
        case ScriptErrorKind::SyntaxOrLoadError:        return "SyntaxOrLoadError";
        case ScriptErrorKind::RuntimeError:             return "RuntimeError";
        case ScriptErrorKind::MemoryLimitExceeded:      return "MemoryLimitExceeded";
        case ScriptErrorKind::InstructionLimitExceeded: return "InstructionLimitExceeded";
        case ScriptErrorKind::WallClockTimeout:         return "WallClockTimeout";
        case ScriptErrorKind::OutputLimitExceeded:      return "OutputLimitExceeded";
        case ScriptErrorKind::Cancelled:                return "Cancelled";
        case ScriptErrorKind::CommitFailed:             return "CommitFailed";
    }
    return "RuntimeError";
}

/// Core virtual-address bookmark entry managed by `ProjectWorkspace` and Lua scripts.
struct ScriptBookmark {
    std::uint64_t virtual_address{0};
    std::string label{};

    auto operator<=>(const ScriptBookmark&) const = default;
};

/// Core annotation and bookmark store targeted by transactional Lua scripts (`WU-28a`).
class ProjectWorkspace {
public:
    ProjectWorkspace() = default;

    void set_label(std::uint64_t virtual_address, std::string name);
    [[nodiscard]] std::optional<std::string> get_label(std::uint64_t virtual_address) const;
    bool erase_label(std::uint64_t virtual_address) noexcept;
    [[nodiscard]] const std::map<std::uint64_t, std::string>& labels() const noexcept {
        return labels_;
    }

    void set_comment(std::uint64_t virtual_address, std::string text);
    [[nodiscard]] std::optional<std::string> get_comment(std::uint64_t virtual_address) const;
    bool erase_comment(std::uint64_t virtual_address) noexcept;
    [[nodiscard]] const std::map<std::uint64_t, std::string>& comments() const noexcept {
        return comments_;
    }

    void add_bookmark(std::uint64_t virtual_address, std::string label);
    void add_or_update_bookmark(std::uint64_t virtual_address, std::string label) {
        add_bookmark(virtual_address, std::move(label));
    }
    [[nodiscard]] std::span<const ScriptBookmark> bookmarks() const noexcept {
        return bookmarks_;
    }

    void clear() noexcept;

private:
    std::map<std::uint64_t, std::string> labels_{};
    std::map<std::uint64_t, std::string> comments_{};
    std::vector<ScriptBookmark> bookmarks_{};
};

/// Contiguous staged byte patch interval produced by `peelf.stage_patch(va, bytes)`.
struct StagedBytePatch {
    std::uint64_t virtual_address{0};
    std::uint64_t file_offset{0};
    std::vector<std::uint8_t> original_bytes{};
    std::vector<std::uint8_t> patched_bytes{};

    auto operator<=>(const StagedBytePatch&) const = default;
};

/// Isolated read-your-writes staging buffer for a single script invocation.
/// No mutations touch `ProjectWorkspace` or `PagedBinaryImage` unless `peelf.commit()` is
/// called and the script exits cleanly without errors or quota violations.
class ScriptTransaction {
public:
    ScriptTransaction() = default;
    explicit ScriptTransaction(const ProjectWorkspace* baseline_workspace);

    void reset(const ProjectWorkspace* baseline_workspace);
    void rollback();

    void stage_label(std::uint64_t virtual_address, std::string name);
    [[nodiscard]] std::optional<std::string> effective_label(
        std::uint64_t virtual_address) const;

    void stage_comment(std::uint64_t virtual_address, std::string text);
    [[nodiscard]] std::optional<std::string> effective_comment(
        std::uint64_t virtual_address) const;

    void stage_bookmark(std::uint64_t virtual_address, std::string label);
    [[nodiscard]] std::span<const ScriptBookmark> effective_bookmarks() const noexcept;

    void stage_byte(std::uint64_t file_offset,
                    std::uint64_t virtual_address,
                    std::uint8_t original_byte,
                    std::uint8_t patched_byte);

    [[nodiscard]] std::optional<std::uint8_t> staged_byte_at_offset(
        std::uint64_t file_offset) const noexcept;

    [[nodiscard]] std::vector<StagedBytePatch> coalesced_patches() const;

    void request_commit(std::string label = "Lua script transaction");
    [[nodiscard]] bool commit_requested() const noexcept { return commit_requested_; }
    [[nodiscard]] const std::string& commit_label() const noexcept { return commit_label_; }

    [[nodiscard]] bool has_staged_patches() const noexcept { return !staged_bytes_.empty(); }
    [[nodiscard]] bool has_staged_annotations() const noexcept {
        return !staged_labels_.empty() || !staged_comments_.empty() || bookmarks_modified_;
    }
    [[nodiscard]] bool has_any_staged_changes() const noexcept {
        return has_staged_patches() || has_staged_annotations();
    }

    [[nodiscard]] const std::map<std::uint64_t, std::optional<std::string>>&
    staged_labels() const noexcept {
        return staged_labels_;
    }
    [[nodiscard]] const std::map<std::uint64_t, std::optional<std::string>>&
    staged_comments() const noexcept {
        return staged_comments_;
    }

    [[nodiscard]] Result<void> apply_to_host(PagedBinaryImage* paged_image,
                                             ProjectWorkspace* workspace) const;

private:
    struct ByteCell {
        std::uint64_t virtual_address{0};
        std::uint8_t original{0};
        std::uint8_t patched{0};
    };

    const ProjectWorkspace* baseline_workspace_{nullptr};
    std::map<std::uint64_t, ByteCell> staged_bytes_{};
    std::map<std::uint64_t, std::optional<std::string>> staged_labels_{};
    std::map<std::uint64_t, std::optional<std::string>> staged_comments_{};
    std::vector<ScriptBookmark> staged_bookmarks_{};
    bool bookmarks_modified_{false};
    bool commit_requested_{false};
    std::string commit_label_{"Lua script transaction"};
};

/// Host target & workspace bindings exposed to a sandboxed Lua 5.4 script run.
struct ScriptContext {
    const IBinaryImage* image{nullptr};
    std::span<const std::uint8_t> raw_bytes{};
    PagedBinaryImage* paged_image{nullptr};
    ProjectWorkspace* workspace{nullptr};
    IProcessSession* live_session{nullptr};
    ICrashDumpSession* crash_dump{nullptr};
    std::optional<TargetCapabilityMatrix> capabilities{};
    bool allow_mutations{true};
    bool is_read_only{false};
    bool remote_gdb_rsp{false};
};

/// Inspectable summary of staged mutations produced during a script run (including dry-runs).
struct ScriptExecutionSummary {
    std::vector<StagedBytePatch> staged_patches{};
    std::map<std::uint64_t, std::optional<std::string>> staged_labels{};
    std::map<std::uint64_t, std::optional<std::string>> staged_comments{};
    std::vector<ScriptBookmark> staged_bookmarks{};
    bool bookmarks_modified{false};
};

/// Complete outcome, telemetry, captured log output, and commit status of a script execution.
struct ScriptExecutionResult {
    bool ok{false};
    bool committed{false};
    bool output_truncated{false};
    ScriptErrorKind error_kind{ScriptErrorKind::None};
    std::string error_message{};
    std::string output{};
    std::uint64_t instructions_executed{0};
    std::size_t peak_memory_bytes{0};
    std::chrono::milliseconds elapsed{0};
    ScriptExecutionSummary staged_summary{};
};

/// Hermetic, quota-enforced MIT Lua 5.4 scripting host with transactional read-your-writes.
class LuaScriptingEngine {
public:
    LuaScriptingEngine() = default;

    [[nodiscard]] ScriptExecutionResult execute(
        std::string_view script_source,
        ScriptContext& context,
        const ScriptLimits& limits = {},
        std::stop_token stop_token = {},
        std::string_view chunk_name = "script.lua") const;
};

/// Convenience entry point executing a Lua 5.4 script with transactional staging.
[[nodiscard]] inline ScriptExecutionResult execute_lua_script(
    std::string_view script_source,
    ScriptContext& context,
    const ScriptLimits& limits = {},
    std::stop_token stop_token = {},
    std::string_view chunk_name = "script.lua") {
    const LuaScriptingEngine engine{};
    return engine.execute(script_source, context, limits, std::move(stop_token), chunk_name);
}

} // namespace peelf
