#include <peelf/scripting.hpp>

#include <peelf/endian_reader.hpp>
#include <peelf/security_audit.hpp>

#include <capstone/capstone.h>

extern "C" {
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
}

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <format>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace peelf {

void LuaStateDeleter::operator()(lua_State* state) const noexcept {
    if (state != nullptr) {
        lua_close(state);
    }
}

UniqueLuaState make_unique_lua_state() noexcept {
    return UniqueLuaState{luaL_newstate()};
}

// ---------------------------------------------------------------------------
// ProjectWorkspace
// ---------------------------------------------------------------------------

void ProjectWorkspace::set_label(std::uint64_t virtual_address, std::string name) {
    if (name.empty()) {
        labels_.erase(virtual_address);
        return;
    }
    labels_[virtual_address] = std::move(name);
}

std::optional<std::string> ProjectWorkspace::get_label(std::uint64_t virtual_address) const {
    const auto it = labels_.find(virtual_address);
    if (it == labels_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool ProjectWorkspace::erase_label(std::uint64_t virtual_address) noexcept {
    return labels_.erase(virtual_address) > 0u;
}

void ProjectWorkspace::set_comment(std::uint64_t virtual_address, std::string text) {
    if (text.empty()) {
        comments_.erase(virtual_address);
        return;
    }
    comments_[virtual_address] = std::move(text);
}

std::optional<std::string> ProjectWorkspace::get_comment(std::uint64_t virtual_address) const {
    const auto it = comments_.find(virtual_address);
    if (it == comments_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool ProjectWorkspace::erase_comment(std::uint64_t virtual_address) noexcept {
    return comments_.erase(virtual_address) > 0u;
}

void ProjectWorkspace::add_bookmark(std::uint64_t virtual_address, std::string label) {
    for (ScriptBookmark& existing : bookmarks_) {
        if (existing.virtual_address == virtual_address) {
            existing.label = std::move(label);
            return;
        }
    }
    bookmarks_.push_back(ScriptBookmark{
        .virtual_address = virtual_address,
        .label = std::move(label),
    });
    std::ranges::sort(bookmarks_, [](const ScriptBookmark& a, const ScriptBookmark& b) noexcept {
        return a.virtual_address < b.virtual_address;
    });
}

void ProjectWorkspace::clear() noexcept {
    labels_.clear();
    comments_.clear();
    bookmarks_.clear();
}

// ---------------------------------------------------------------------------
// ScriptTransaction
// ---------------------------------------------------------------------------

ScriptTransaction::ScriptTransaction(const ProjectWorkspace* baseline_workspace) {
    reset(baseline_workspace);
}

void ScriptTransaction::reset(const ProjectWorkspace* baseline_workspace) {
    baseline_workspace_ = baseline_workspace;
    staged_bytes_.clear();
    staged_labels_.clear();
    staged_comments_.clear();
    staged_bookmarks_.clear();
    if (baseline_workspace_ != nullptr) {
        const auto existing = baseline_workspace_->bookmarks();
        staged_bookmarks_.assign(existing.begin(), existing.end());
    }
    bookmarks_modified_ = false;
    commit_requested_ = false;
    commit_label_ = "Lua script transaction";
}

void ScriptTransaction::rollback() {
    reset(baseline_workspace_);
}

void ScriptTransaction::stage_label(std::uint64_t virtual_address, std::string name) {
    if (name.empty()) {
        staged_labels_[virtual_address] = std::nullopt;
    } else {
        staged_labels_[virtual_address] = std::move(name);
    }
}

std::optional<std::string> ScriptTransaction::effective_label(
    std::uint64_t virtual_address) const {
    const auto it = staged_labels_.find(virtual_address);
    if (it != staged_labels_.end()) {
        return it->second;
    }
    if (baseline_workspace_ != nullptr) {
        return baseline_workspace_->get_label(virtual_address);
    }
    return std::nullopt;
}

void ScriptTransaction::stage_comment(std::uint64_t virtual_address, std::string text) {
    if (text.empty()) {
        staged_comments_[virtual_address] = std::nullopt;
    } else {
        staged_comments_[virtual_address] = std::move(text);
    }
}

std::optional<std::string> ScriptTransaction::effective_comment(
    std::uint64_t virtual_address) const {
    const auto it = staged_comments_.find(virtual_address);
    if (it != staged_comments_.end()) {
        return it->second;
    }
    if (baseline_workspace_ != nullptr) {
        return baseline_workspace_->get_comment(virtual_address);
    }
    return std::nullopt;
}

void ScriptTransaction::stage_bookmark(std::uint64_t virtual_address, std::string label) {
    bookmarks_modified_ = true;
    for (ScriptBookmark& existing : staged_bookmarks_) {
        if (existing.virtual_address == virtual_address) {
            existing.label = std::move(label);
            return;
        }
    }
    staged_bookmarks_.push_back(ScriptBookmark{
        .virtual_address = virtual_address,
        .label = std::move(label),
    });
    std::ranges::sort(
        staged_bookmarks_,
        [](const ScriptBookmark& a, const ScriptBookmark& b) noexcept {
            return a.virtual_address < b.virtual_address;
        });
}

std::span<const ScriptBookmark> ScriptTransaction::effective_bookmarks() const noexcept {
    return staged_bookmarks_;
}

void ScriptTransaction::stage_byte(std::uint64_t file_offset,
                                   std::uint64_t virtual_address,
                                   std::uint8_t original_byte,
                                   std::uint8_t patched_byte) {
    const auto it = staged_bytes_.find(file_offset);
    if (it != staged_bytes_.end()) {
        it->second.virtual_address = virtual_address;
        it->second.patched = patched_byte;
        return;
    }
    staged_bytes_.emplace(file_offset, ByteCell{
        .virtual_address = virtual_address,
        .original = original_byte,
        .patched = patched_byte,
    });
}

std::optional<std::uint8_t> ScriptTransaction::staged_byte_at_offset(
    std::uint64_t file_offset) const noexcept {
    const auto it = staged_bytes_.find(file_offset);
    if (it == staged_bytes_.end()) {
        return std::nullopt;
    }
    return it->second.patched;
}

std::vector<StagedBytePatch> ScriptTransaction::coalesced_patches() const {
    std::vector<StagedBytePatch> result;
    for (const auto& [off, cell] : staged_bytes_) {
        if (!result.empty()) {
            StagedBytePatch& back = result.back();
            const auto prev_len = static_cast<std::uint64_t>(back.patched_bytes.size());
            if (off > back.file_offset &&
                (off - back.file_offset) == prev_len &&
                cell.virtual_address > back.virtual_address &&
                (cell.virtual_address - back.virtual_address) == prev_len) {
                back.original_bytes.push_back(cell.original);
                back.patched_bytes.push_back(cell.patched);
                continue;
            }
        }
        StagedBytePatch interval{};
        interval.virtual_address = cell.virtual_address;
        interval.file_offset = off;
        interval.original_bytes.push_back(cell.original);
        interval.patched_bytes.push_back(cell.patched);
        result.push_back(std::move(interval));
    }
    return result;
}

void ScriptTransaction::request_commit(std::string label) {
    commit_requested_ = true;
    if (!label.empty()) {
        commit_label_ = std::move(label);
    }
}

Result<void> ScriptTransaction::apply_to_host(PagedBinaryImage* paged_image,
                                              ProjectWorkspace* workspace) const {
    const std::vector<StagedBytePatch> patches = coalesced_patches();
    if (!patches.empty()) {
        if (paged_image == nullptr) {
            return make_error(
                "Cannot commit staged byte patches: ScriptContext has no PagedBinaryImage");
        }
        PatchTransaction patch_tx = paged_image->begin_transaction(commit_label_);
        for (const StagedBytePatch& p : patches) {
            if (auto wr = patch_tx.write(p.file_offset, p.patched_bytes); !wr.has_value()) {
                patch_tx.rollback();
                return wr;
            }
        }
        if (auto cm = patch_tx.commit(); !cm.has_value()) {
            patch_tx.rollback();
            return cm;
        }
    }

    if (has_staged_annotations()) {
        if (workspace == nullptr) {
            return make_error(
                "Cannot commit staged annotations: ScriptContext has no ProjectWorkspace");
        }
        for (const auto& [va, maybe_label] : staged_labels_) {
            if (maybe_label.has_value() && !maybe_label->empty()) {
                workspace->set_label(va, *maybe_label);
            } else {
                workspace->erase_label(va);
            }
        }
        for (const auto& [va, maybe_comment] : staged_comments_) {
            if (maybe_comment.has_value() && !maybe_comment->empty()) {
                workspace->set_comment(va, *maybe_comment);
            } else {
                workspace->erase_comment(va);
            }
        }
        if (bookmarks_modified_) {
            for (const ScriptBookmark& bm : staged_bookmarks_) {
                workspace->add_bookmark(bm.virtual_address, bm.label);
            }
        }
    }
    return {};
}

// ---------------------------------------------------------------------------
// Internal Lua C / C++ Boundary & Sandbox Implementation
//
// STRICT `longjmp` ISOLATION CONTRACT:
// Standard Lua 5.4 compiled as C unwinds via `longjmp` on `lua_error`, `luaL_error`,
// and out-of-memory (`LUA_ERRMEM` inside `lua_push*`, `lua_createtable`, `lua_setfield`,
// etc.). Therefore:
//   1. `ScriptRuntimeState` (and all reusable `scratch_*` C++ containers) lives on the
//      caller stack in `LuaScriptingEngine::execute`, *above* the top-level `lua_pcall`.
//   2. Every `lua_CFunction` and `lua_Hook` holds ONLY trivially destructible POD locals.
//   3. All C++ work (`std::string`, `std::vector`, `Result<T>`, Capstone RAII,
//      `SecurityAuditReport`, `ScriptTransaction`) executes inside `noexcept` helper
//      functions that never invoke throwing/allocating Lua C APIs and finish running
//      all C++ destructors before returning a POD status to the outer C trampoline.
// ---------------------------------------------------------------------------

namespace {

constexpr std::size_t kMaxSingleReadBytes = 16u * 1024u * 1024u;
constexpr std::size_t kMaxMaterializedFileBytes = 64u * 1024u * 1024u;
constexpr std::size_t kDefaultDisasmCount = 16u;
constexpr std::size_t kMaxDisasmCount = 4096u;
constexpr std::size_t kDefaultStringsLimit = 4096u;
constexpr std::size_t kMaxStringsLimit = 65536u;

[[nodiscard]] std::optional<std::uint64_t> checked_add(std::uint64_t a,
                                                       std::uint64_t b) noexcept {
    if (a > std::numeric_limits<std::uint64_t>::max() - b) {
        return std::nullopt;
    }
    return a + b;
}

struct ScratchDisasmItem {
    std::uint64_t address{0};
    std::vector<std::uint8_t> bytes{};
    std::string mnemonic{};
    std::string operands{};
    std::string text{};
};

struct ScratchTargetInfo {
    std::string_view format{"Unknown"};
    std::string_view kind{"Unknown"};
    std::string_view arch{"Unknown"};
    std::string_view endianness{"little-endian"};
    int bitness{64};
    std::uint64_t image_base{0};
    std::uint64_t entry_point{0};
    bool is_read_only{true};
    bool allow_mutations{false};
};

class ScopedCapstoneHandle {
public:
    ScopedCapstoneHandle() noexcept = default;
    ~ScopedCapstoneHandle() noexcept {
        if (handle_ != 0) {
            cs_close(&handle_);
        }
    }

    ScopedCapstoneHandle(const ScopedCapstoneHandle&) = delete;
    ScopedCapstoneHandle& operator=(const ScopedCapstoneHandle&) = delete;
    ScopedCapstoneHandle(ScopedCapstoneHandle&&) = delete;
    ScopedCapstoneHandle& operator=(ScopedCapstoneHandle&&) = delete;

    [[nodiscard]] csh* put() noexcept { return &handle_; }
    [[nodiscard]] csh get() const noexcept { return handle_; }

private:
    csh handle_{0};
};

class ScopedCapstoneInsns {
public:
    ScopedCapstoneInsns(cs_insn* insns, std::size_t count) noexcept
        : insns_(insns), count_(count) {}

    ~ScopedCapstoneInsns() noexcept {
        if (insns_ != nullptr) {
            cs_free(insns_, count_);
        }
    }

    ScopedCapstoneInsns(const ScopedCapstoneInsns&) = delete;
    ScopedCapstoneInsns& operator=(const ScopedCapstoneInsns&) = delete;
    ScopedCapstoneInsns(ScopedCapstoneInsns&&) = delete;
    ScopedCapstoneInsns& operator=(ScopedCapstoneInsns&&) = delete;

private:
    cs_insn* insns_{nullptr};
    std::size_t count_{0};
};

struct ScriptRuntimeState {
    ScriptContext* context{nullptr};
    TargetCapabilityMatrix capabilities{};
    bool effective_read_only{true};
    ScriptLimits limits{};
    std::stop_token stop_token{};
    std::chrono::steady_clock::time_point start_time{};
    int hook_step{1};

    std::string_view script_source{};
    std::string chunk_label{};

    std::size_t live_memory_bytes{0};
    std::size_t peak_memory_bytes{0};
    bool memory_limit_exceeded{false};
    bool enforce_memory_quota{false};

    std::uint64_t instructions_executed{0};
    ScriptErrorKind fatal_abort_kind{ScriptErrorKind::None};
    std::string fatal_abort_message{};
    ScriptErrorKind load_error_kind{ScriptErrorKind::None};

    std::string output{};
    bool output_truncated{false};

    ScriptTransaction transaction{};

    // Host-owned scratch buffers reused across `lua_CFunction` bindings so zero
    // non-trivial C++ objects ever sit on a `longjmp`-unwindable C stack frame.
    std::string scratch_error{};
    std::string scratch_text{};
    std::vector<std::uint8_t> scratch_bytes{};
    std::vector<HeadlessExtractedString> scratch_strings{};
    std::vector<ScratchDisasmItem> scratch_disasm{};
    SecurityAuditReport scratch_audit{};
    ScratchTargetInfo scratch_target_info{};
};

void* sandbox_lua_alloc(void* ud, void* ptr, std::size_t osize, std::size_t nsize) noexcept {
    auto* rt = static_cast<ScriptRuntimeState*>(ud);
    // Per Lua 5.4 manual: when `ptr == nullptr`, `osize` encodes the Lua type tag, NOT bytes.
    const std::size_t actual_old_size = (ptr != nullptr) ? osize : 0u;

    if (nsize == 0u) {
        if (ptr != nullptr) {
            std::free(ptr);
            rt->live_memory_bytes = (rt->live_memory_bytes >= actual_old_size)
                ? (rt->live_memory_bytes - actual_old_size)
                : 0u;
        }
        return nullptr;
    }

    if (rt->enforce_memory_quota && nsize > actual_old_size) {
        const std::size_t growth = nsize - actual_old_size;
        if (growth > rt->limits.max_memory_bytes ||
            rt->live_memory_bytes > (rt->limits.max_memory_bytes - growth)) {
            rt->memory_limit_exceeded = true;
            return nullptr;
        }
    }

    void* next = std::realloc(ptr, nsize);
    if (next == nullptr) {
        return nullptr;
    }

    if (nsize >= actual_old_size) {
        const std::size_t growth = nsize - actual_old_size;
        if (rt->live_memory_bytes <= (std::numeric_limits<std::size_t>::max() - growth)) {
            rt->live_memory_bytes += growth;
        } else {
            rt->live_memory_bytes = std::numeric_limits<std::size_t>::max();
        }
    } else {
        const std::size_t shrink = actual_old_size - nsize;
        rt->live_memory_bytes = (rt->live_memory_bytes >= shrink)
            ? (rt->live_memory_bytes - shrink)
            : 0u;
    }

    if (rt->live_memory_bytes > rt->peak_memory_bytes) {
        rt->peak_memory_bytes = rt->live_memory_bytes;
    }
    return next;
}

int sandbox_panic_handler(lua_State* /*L*/) noexcept {
    return 0;
}

[[nodiscard]] ScriptRuntimeState* get_runtime_upvalue(lua_State* L) noexcept {
    return static_cast<ScriptRuntimeState*>(lua_touserdata(L, lua_upvalueindex(1)));
}

void set_scratch_error(ScriptRuntimeState* rt, std::string_view msg) noexcept {
    try {
        rt->scratch_error.assign(msg.data(), msg.size());
    } catch (...) {
        rt->scratch_error.clear();
    }
}

[[noreturn]] int raise_scratch_error(lua_State* L, const ScriptRuntimeState* rt) {
    if (!rt->scratch_error.empty()) {
        lua_pushlstring(L, rt->scratch_error.data(), rt->scratch_error.size());
    } else {
        lua_pushliteral(L, "peelf scripting host error");
    }
    lua_error(L);
    std::unreachable();
}

[[noreturn]] int raise_literal_error(lua_State* L, const char* msg) {
    lua_pushstring(L, msg);
    lua_error(L);
    std::unreachable();
}

[[nodiscard]] const char* check_hook_limits_noexcept(ScriptRuntimeState* rt) noexcept {
    const auto step = static_cast<std::uint64_t>(rt->hook_step > 0 ? rt->hook_step : 1);
    if (rt->instructions_executed <= (std::numeric_limits<std::uint64_t>::max() - step)) {
        rt->instructions_executed += step;
    } else {
        rt->instructions_executed = std::numeric_limits<std::uint64_t>::max();
    }

    if (rt->stop_token.stop_requested()) {
        rt->fatal_abort_kind = ScriptErrorKind::Cancelled;
        try {
            rt->fatal_abort_message = "script cancelled via stop_token";
        } catch (...) {
        }
        return rt->fatal_abort_message.empty()
            ? "script cancelled via stop_token"
            : rt->fatal_abort_message.c_str();
    }

    if (rt->limits.max_instructions == 0u ||
        rt->instructions_executed > rt->limits.max_instructions) {
        rt->fatal_abort_kind = ScriptErrorKind::InstructionLimitExceeded;
        try {
            rt->fatal_abort_message = std::format(
                "script exceeded max_instructions quota ({})",
                rt->limits.max_instructions);
        } catch (...) {
        }
        return rt->fatal_abort_message.empty()
            ? "script exceeded max_instructions quota"
            : rt->fatal_abort_message.c_str();
    }

    const auto now = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - rt->start_time);
    if (rt->limits.wall_clock_timeout.count() <= 0 ||
        elapsed > rt->limits.wall_clock_timeout) {
        rt->fatal_abort_kind = ScriptErrorKind::WallClockTimeout;
        try {
            rt->fatal_abort_message = std::format(
                "script exceeded wall_clock_timeout ({} ms)",
                rt->limits.wall_clock_timeout.count());
        } catch (...) {
        }
        return rt->fatal_abort_message.empty()
            ? "script exceeded wall_clock_timeout"
            : rt->fatal_abort_message.c_str();
    }

    return nullptr;
}

void sandbox_instruction_hook(lua_State* L, lua_Debug* /*ar*/) {
    void* ud = nullptr;
    (void)lua_getallocf(L, &ud);
    auto* rt = static_cast<ScriptRuntimeState*>(ud);
    if (rt == nullptr) {
        return;
    }
    const char* err = check_hook_limits_noexcept(rt);
    if (err != nullptr) {
        lua_pushstring(L, err);
        lua_error(L);
    }
}

// ---------------------------------------------------------------------------
// Output capture (`print` & `peelf.log`)
// ---------------------------------------------------------------------------

void begin_log_line_noexcept(ScriptRuntimeState* rt) noexcept {
    rt->scratch_text.clear();
}

bool append_log_piece_noexcept(ScriptRuntimeState* rt,
                               bool add_tab,
                               const char* ptr,
                               std::size_t len) noexcept {
    try {
        if (add_tab) {
            rt->scratch_text.push_back('\t');
        }
        if (ptr != nullptr && len > 0u) {
            rt->scratch_text.append(ptr, len);
        }
        return true;
    } catch (...) {
        set_scratch_error(rt, "out of host memory while formatting script output");
        return false;
    }
}

const char* finish_log_line_noexcept(ScriptRuntimeState* rt) noexcept {
    try {
        rt->scratch_text.push_back('\n');
        const std::size_t cap = rt->limits.max_output_bytes;
        const std::size_t cur = rt->output.size();
        const std::size_t avail = (cur < cap) ? (cap - cur) : 0u;
        if (rt->scratch_text.size() <= avail) {
            rt->output.append(rt->scratch_text);
            return nullptr;
        }
        if (avail > 0u) {
            rt->output.append(rt->scratch_text.data(), avail);
        }
        rt->output_truncated = true;
        rt->fatal_abort_kind = ScriptErrorKind::OutputLimitExceeded;
        rt->fatal_abort_message = std::format(
            "script exceeded max_output_bytes quota ({} bytes)", cap);
        return rt->fatal_abort_message.c_str();
    } catch (...) {
        rt->output_truncated = true;
        rt->fatal_abort_kind = ScriptErrorKind::OutputLimitExceeded;
        return "script exceeded max_output_bytes quota";
    }
}

int lua_sandbox_print(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    const int nargs = lua_gettop(L);
    begin_log_line_noexcept(rt);
    for (int i = 1; i <= nargs; ++i) {
        std::size_t piece_len = 0u;
        const char* piece_ptr = luaL_tolstring(L, i, &piece_len);
        const bool piece_ok = append_log_piece_noexcept(rt, i > 1, piece_ptr, piece_len);
        lua_pop(L, 1);
        if (!piece_ok) {
            return raise_scratch_error(L, rt);
        }
    }
    const char* quota_err = finish_log_line_noexcept(rt);
    if (quota_err != nullptr) {
        return raise_literal_error(L, quota_err);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Sandboxed `pcall`, `xpcall`, and text-only `load`
// ---------------------------------------------------------------------------

int lua_sandbox_pcall(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    if (lua_gettop(L) < 1) {
        return raise_literal_error(L, "bad argument #1 to 'pcall' (value expected)");
    }
    const int rc = lua_pcall(L, lua_gettop(L) - 1, LUA_MULTRET, 0);
    if (rc != LUA_OK) {
        if (rt->fatal_abort_kind != ScriptErrorKind::None || rc == LUA_ERRMEM) {
            lua_error(L);
            std::unreachable();
        }
        lua_pushboolean(L, 0);
        lua_insert(L, 1);
        return 2;
    }
    lua_pushboolean(L, 1);
    lua_insert(L, 1);
    return lua_gettop(L);
}

int lua_sandbox_xpcall(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    const int top = lua_gettop(L);
    if (top < 2) {
        return raise_literal_error(L, "bad argument #2 to 'xpcall' (function expected)");
    }
    if (lua_type(L, 2) != LUA_TFUNCTION) {
        return raise_literal_error(L, "bad argument #2 to 'xpcall' (function expected)");
    }
    // Stack: [1]=f, [2]=msgh, [3..top]=args -> move msgh to [1], f to [2], args to [3..top]
    lua_pushvalue(L, 2);
    lua_remove(L, 2);
    lua_insert(L, 1);
    const int rc = lua_pcall(L, top - 2, LUA_MULTRET, 1);
    if (rc != LUA_OK) {
        if (rt->fatal_abort_kind != ScriptErrorKind::None || rc == LUA_ERRMEM) {
            lua_error(L);
            std::unreachable();
        }
        lua_remove(L, 1); // remove msgh
        lua_pushboolean(L, 0);
        lua_insert(L, 1);
        return 2;
    }
    lua_remove(L, 1); // remove msgh
    lua_pushboolean(L, 1);
    lua_insert(L, 1);
    return lua_gettop(L);
}

struct SandboxReaderState {
    bool done{false};
};

const char* sandbox_chunk_reader(lua_State* L, void* data, std::size_t* size) {
    auto* st = static_cast<SandboxReaderState*>(data);
    if (st->done) {
        *size = 0u;
        return nullptr;
    }
    luaL_checkstack(L, 2, "too many nested functions");
    lua_pushvalue(L, 1); // reader function at index 1
    lua_call(L, 0, 1);
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        st->done = true;
        *size = 0u;
        return nullptr;
    }
    if (lua_type(L, -1) != LUA_TSTRING) {
        return static_cast<const char*>(
            (luaL_error(L, "reader function must return a string"), nullptr));
    }
    // Keep returned string anchored in reserved slot 5 so pointer remains valid until next call.
    lua_replace(L, 5);
    return lua_tolstring(L, 5, size);
}

int lua_sandbox_load(lua_State* L) {
    const int chunk_type = lua_type(L, 1);
    if (chunk_type != LUA_TSTRING && chunk_type != LUA_TFUNCTION) {
        return raise_literal_error(
            L, "bad argument #1 to 'load' (function or string expected)");
    }

    const char* chunk_name = nullptr;
    if (!lua_isnoneornil(L, 2)) {
        if (lua_type(L, 2) != LUA_TSTRING) {
            return raise_literal_error(L, "bad argument #2 to 'load' (string expected)");
        }
        chunk_name = lua_tostring(L, 2);
    }

    if (!lua_isnoneornil(L, 3)) {
        if (lua_type(L, 3) != LUA_TSTRING) {
            return raise_literal_error(L, "bad argument #3 to 'load' (string expected)");
        }
        std::size_t mode_len = 0u;
        const char* mode_str = lua_tolstring(L, 3, &mode_len);
        if (mode_len != 1u || mode_str[0] != 't') {
            lua_pushnil(L);
            lua_pushliteral(
                L, "sandbox forbids binary chunk mode; only text mode ('t') is permitted");
            return 2;
        }
    }

    const bool has_env = !lua_isnone(L, 4);
    int status = LUA_ERRSYNTAX;
    if (chunk_type == LUA_TSTRING) {
        std::size_t src_len = 0u;
        const char* src_ptr = lua_tolstring(L, 1, &src_len);
        if (src_len > 0u && src_ptr[0] == '\x1b') {
            lua_pushnil(L);
            lua_pushliteral(
                L, "sandbox forbids binary Lua bytecode chunks (mode is 't')");
            return 2;
        }
        const char* effective_name = (chunk_name != nullptr) ? chunk_name : src_ptr;
        status = luaL_loadbufferx(L, src_ptr, src_len, effective_name, "t");
    } else {
        const char* effective_name = (chunk_name != nullptr) ? chunk_name : "=(load)";
        lua_settop(L, 5); // reserve slot 5 for reader anchor
        SandboxReaderState reader_state{};
        status = lua_load(L, &sandbox_chunk_reader, &reader_state, effective_name, "t");
    }

    if (status == LUA_OK) {
        if (has_env) {
            lua_pushvalue(L, 4);
            if (lua_setupvalue(L, -2, 1) == nullptr) {
                lua_pop(L, 1);
            }
        }
        return 1;
    }

    lua_pushnil(L);
    lua_insert(L, -2); // place nil before error message
    return 2;
}

// ---------------------------------------------------------------------------
// Effective target helpers (noexcept inner C++ layer)
// ---------------------------------------------------------------------------

[[nodiscard]] IProcessSession* active_process_session(const ScriptContext& ctx) noexcept {
    if (ctx.live_session != nullptr) {
        return ctx.live_session;
    }
    return ctx.crash_dump;
}

[[nodiscard]] std::optional<std::uint64_t> static_backing_size(
    const ScriptContext& ctx) noexcept {
    if (ctx.paged_image != nullptr) {
        return ctx.paged_image->size();
    }
    if (!ctx.raw_bytes.empty()) {
        return static_cast<std::uint64_t>(ctx.raw_bytes.size());
    }
    return std::nullopt;
}

[[nodiscard]] Result<std::uint8_t> read_baseline_static_byte(
    const ScriptContext& ctx,
    std::uint64_t file_offset) {
    if (ctx.paged_image != nullptr) {
        auto bytes = ctx.paged_image->read_effective(file_offset, 1u);
        if (!bytes.has_value() || bytes->empty()) {
            return make_error(bytes.has_value()
                                  ? std::string{"Empty byte read from PagedBinaryImage"}
                                  : bytes.error().message);
        }
        return (*bytes)[0];
    }
    if (!ctx.raw_bytes.empty()) {
        if (file_offset >= ctx.raw_bytes.size()) {
            return make_error("File offset exceeds raw binary buffer size");
        }
        return ctx.raw_bytes[static_cast<std::size_t>(file_offset)];
    }
    if (ctx.image != nullptr) {
        auto bytes = ctx.image->read_bytes_at_offset(file_offset, 1u);
        if (!bytes.has_value() || bytes->empty()) {
            return make_error(bytes.has_value()
                                  ? std::string{"Empty byte read from IBinaryImage"}
                                  : bytes.error().message);
        }
        return (*bytes)[0];
    }
    return make_error("No static binary backing image is attached");
}

[[nodiscard]] Result<std::vector<std::uint8_t>> read_effective_va_span(
    const ScriptRuntimeState& rt,
    std::uint64_t va,
    std::size_t len) {
    if (len > kMaxSingleReadBytes) {
        return make_error("read length exceeds single-read sandbox limit (16 MiB)");
    }
    const auto end_va = checked_add(va, static_cast<std::uint64_t>(len));
    if (!end_va.has_value()) {
        return make_error("virtual address range overflows 64-bit address space");
    }

    const ScriptContext& ctx = *rt.context;
    if (ctx.image != nullptr) {
        if (len == 0u) {
            if (ctx.image->virtual_address_to_file_offset(va).has_value()) {
                return std::vector<std::uint8_t>{};
            }
            auto probe = ctx.image->read_bytes_at_va(va, 0u);
            if (probe.has_value()) {
                return std::vector<std::uint8_t>{};
            }
            return make_error(std::format("virtual address 0x{:x} is not mapped", va));
        }

        std::vector<std::uint8_t> out(len, 0u);
        // Baseline read: prefer PagedBinaryImage (reflects previously committed patches),
        // then raw_bytes, then IBinaryImage::read_bytes_at_va.
        bool filled_from_image_va = false;
        if (ctx.paged_image == nullptr) {
            auto direct = ctx.image->read_bytes_at_va(va, len);
            if (direct.has_value() && direct->size() == len) {
                out = std::move(*direct);
                filled_from_image_va = true;
            }
        }

        for (std::size_t i = 0u; i < len; ++i) {
            const std::uint64_t cur_va = va + static_cast<std::uint64_t>(i);
            const auto maybe_off = ctx.image->virtual_address_to_file_offset(cur_va);
            if (maybe_off.has_value()) {
                if (const auto staged = rt.transaction.staged_byte_at_offset(*maybe_off);
                    staged.has_value()) {
                    out[i] = *staged;
                    continue;
                }
                if (!filled_from_image_va) {
                    auto b = read_baseline_static_byte(ctx, *maybe_off);
                    if (!b.has_value()) {
                        return std::unexpected(b.error());
                    }
                    out[i] = *b;
                }
            } else if (!filled_from_image_va) {
                // Might be zero-filled BSS tail inside a mapped section/segment.
                auto z = ctx.image->read_bytes_at_va(cur_va, 1u);
                if (!z.has_value() || z->empty()) {
                    return make_error(
                        std::format("virtual address 0x{:x} is not mapped", cur_va));
                }
                out[i] = (*z)[0];
            }
        }
        return out;
    }

    if (IProcessSession* sess = active_process_session(ctx); sess != nullptr) {
        std::vector<std::uint8_t> out(len, 0u);
        if (len == 0u) {
            return out;
        }
        auto nread = sess->read_memory(va, out);
        if (!nread.has_value()) {
            return std::unexpected(nread.error());
        }
        if (*nread != len) {
            return make_error(std::format(
                "short read at virtual address 0x{:x} ({} of {} bytes readable)",
                va, *nread, len));
        }
        return out;
    }

    return make_error("no binary image or process session is bound to ScriptContext");
}

[[nodiscard]] Result<std::vector<std::uint8_t>> materialize_effective_file_bytes(
    const ScriptRuntimeState& rt) {
    const ScriptContext& ctx = *rt.context;
    std::vector<std::uint8_t> buf;
    if (ctx.paged_image != nullptr) {
        const std::uint64_t sz = ctx.paged_image->size();
        if (sz > kMaxMaterializedFileBytes) {
            return make_error("binary exceeds maximum in-script full-file scan limit (64 MiB)");
        }
        auto rd = ctx.paged_image->read_effective(0u, sz);
        if (!rd.has_value()) {
            return std::unexpected(rd.error());
        }
        buf = std::move(*rd);
    } else if (!ctx.raw_bytes.empty()) {
        if (ctx.raw_bytes.size() > kMaxMaterializedFileBytes) {
            return make_error("binary exceeds maximum in-script full-file scan limit (64 MiB)");
        }
        buf.assign(ctx.raw_bytes.begin(), ctx.raw_bytes.end());
    } else if (ctx.image != nullptr) {
        // Fallback: determine upper file extent from sections/segments if raw_bytes was attached internally.
        std::uint64_t max_end = 0u;
        for (const Section& s : ctx.image->sections()) {
            if (const auto end = checked_add(s.file_offset, s.file_size); end.has_value()) {
                max_end = std::max(max_end, *end);
            }
        }
        for (const Segment& seg : ctx.image->segments()) {
            if (const auto end = checked_add(seg.file_offset, seg.file_size); end.has_value()) {
                max_end = std::max(max_end, *end);
            }
        }
        if (ctx.image->container_slice_size() != 0u) {
            if (const auto end = checked_add(
                    ctx.image->container_slice_offset(),
                    ctx.image->container_slice_size());
                end.has_value()) {
                max_end = std::max(max_end, *end);
            }
        }
        if (max_end > 0u && max_end <= kMaxMaterializedFileBytes) {
            if (auto rd = ctx.image->read_bytes_at_offset(0u, static_cast<std::size_t>(max_end));
                rd.has_value()) {
                buf = std::move(*rd);
            }
        }
    }

    for (const StagedBytePatch& patch : rt.transaction.coalesced_patches()) {
        const auto end_off = checked_add(
            patch.file_offset,
            static_cast<std::uint64_t>(patch.patched_bytes.size()));
        if (end_off.has_value() && *end_off <= buf.size()) {
            std::copy(patch.patched_bytes.begin(),
                      patch.patched_bytes.end(),
                      buf.begin() + static_cast<std::ptrdiff_t>(patch.file_offset));
        }
    }
    return buf;
}

[[nodiscard]] bool verify_mutation_allowed_noexcept(ScriptRuntimeState* rt,
                                                    bool require_static_patching) noexcept {
    try {
        if (!rt->context->allow_mutations) {
            rt->scratch_error = "mutations are disabled for this script execution (allow_mutations == false)";
            return false;
        }
        if (rt->effective_read_only) {
            rt->scratch_error =
                "target is strictly read-only (live process, crash dump, or remote session); mutations are forbidden";
            return false;
        }
        if (require_static_patching) {
            const Capability& cap = rt->capabilities[Operation::StaticPatching];
            if (!cap.can_execute()) {
                rt->scratch_error = std::format(
                    "StaticPatching capability is unavailable for target: {}",
                    cap.reason);
                return false;
            }
        }
        return true;
    } catch (...) {
        rt->scratch_error.clear();
        return false;
    }
}

// ---------------------------------------------------------------------------
// Argument parsing helpers (pure POD, zero allocation, zero longjmp)
// ---------------------------------------------------------------------------

[[nodiscard]] bool parse_va_arg(lua_State* L, int idx, std::uint64_t* out_va) noexcept {
    int is_int = 0;
    const lua_Integer raw = lua_tointegerx(L, idx, &is_int);
    if (is_int == 0) {
        return false;
    }
    *out_va = static_cast<std::uint64_t>(raw);
    return true;
}

[[nodiscard]] bool parse_nonneg_u64_arg(lua_State* L, int idx, std::uint64_t* out_val) noexcept {
    int is_int = 0;
    const lua_Integer raw = lua_tointegerx(L, idx, &is_int);
    if (is_int == 0 || raw < 0) {
        return false;
    }
    *out_val = static_cast<std::uint64_t>(raw);
    return true;
}

[[nodiscard]] Endianness target_default_endianness(const ScriptRuntimeState& rt) noexcept {
    if (rt.context->image != nullptr) {
        return rt.context->image->endianness();
    }
    if (IProcessSession* sess = active_process_session(*rt.context); sess != nullptr) {
        return sess->info().endianness;
    }
    return rt.capabilities.profile().endianness;
}

[[nodiscard]] bool parse_optional_endianness(lua_State* L,
                                             int idx,
                                             Endianness fallback,
                                             Endianness* out_endian) noexcept {
    if (lua_isnoneornil(L, idx)) {
        *out_endian = fallback;
        return true;
    }
    if (lua_type(L, idx) != LUA_TSTRING) {
        return false;
    }
    std::size_t len = 0u;
    const char* s = lua_tolstring(L, idx, &len);
    const std::string_view sv{s, len};
    if (sv == "le" || sv == "little" || sv == "little-endian") {
        *out_endian = Endianness::Little;
        return true;
    }
    if (sv == "be" || sv == "big" || sv == "big-endian") {
        *out_endian = Endianness::Big;
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// `peelf.*` bindings: noexcept inner helpers + POD C trampolines
// ---------------------------------------------------------------------------

void prepare_target_info_noexcept(ScriptRuntimeState* rt) noexcept {
    ScratchTargetInfo info{};
    const ScriptContext& ctx = *rt->context;
    if (ctx.image != nullptr) {
        info.format = to_string(ctx.image->format());
        info.kind = to_string(ctx.image->kind());
        info.arch = to_string(ctx.image->architecture());
        info.endianness = to_string(ctx.image->endianness());
        info.bitness = ctx.image->is_64bit() ? 64 : 32;
        info.image_base = ctx.image->image_base();
        info.entry_point = ctx.image->entry_point();
    } else if (IProcessSession* sess = active_process_session(ctx); sess != nullptr) {
        const ProcessInfo& pinfo = sess->info();
        info.format = to_string(rt->capabilities.profile().format);
        info.kind = to_string(rt->capabilities.profile().image_kind);
        info.arch = to_string(pinfo.architecture);
        info.endianness = to_string(pinfo.endianness);
        info.bitness = pinfo.is_64bit ? 64 : 32;
        info.image_base = 0u;
        info.entry_point = 0u;
    } else {
        const TargetProfile& prof = rt->capabilities.profile();
        info.format = to_string(prof.format);
        info.kind = to_string(prof.image_kind);
        info.arch = to_string(prof.architecture);
        info.endianness = to_string(prof.endianness);
        info.bitness = (prof.address_width == AddressWidth::Bits64) ? 64 : 32;
    }
    info.is_read_only = rt->effective_read_only || !ctx.allow_mutations;
    info.allow_mutations = ctx.allow_mutations && !rt->effective_read_only;
    rt->scratch_target_info = info;
}

int lua_peelf_target_info(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    prepare_target_info_noexcept(rt);
    const ScratchTargetInfo& info = rt->scratch_target_info;

    lua_createtable(L, 0, 9);
    lua_pushlstring(L, info.format.data(), info.format.size());
    lua_setfield(L, -2, "format");
    lua_pushlstring(L, info.kind.data(), info.kind.size());
    lua_setfield(L, -2, "kind");
    lua_pushlstring(L, info.arch.data(), info.arch.size());
    lua_setfield(L, -2, "arch");
    lua_pushinteger(L, static_cast<lua_Integer>(info.bitness));
    lua_setfield(L, -2, "bitness");
    lua_pushlstring(L, info.endianness.data(), info.endianness.size());
    lua_setfield(L, -2, "endianness");
    lua_pushinteger(L, static_cast<lua_Integer>(info.image_base));
    lua_setfield(L, -2, "image_base");
    lua_pushinteger(L, static_cast<lua_Integer>(info.entry_point));
    lua_setfield(L, -2, "entry_point");
    lua_pushboolean(L, info.is_read_only ? 1 : 0);
    lua_setfield(L, -2, "is_read_only");
    lua_pushboolean(L, info.allow_mutations ? 1 : 0);
    lua_setfield(L, -2, "allow_mutations");
    return 1;
}

int lua_peelf_capabilities(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    const auto entries = rt->capabilities.entries();
    lua_createtable(L, 0, static_cast<int>(entries.size()));
    for (std::size_t i = 0u; i < entries.size(); ++i) {
        const Capability& cap = entries[i];
        const std::string_view op_name = to_string(cap.operation);
        const std::string_view state_name = to_string(cap.state);

        const bool effective_can_execute =
            cap.can_execute() &&
            (cap.operation != Operation::StaticPatching ||
             (rt->context->allow_mutations && !rt->effective_read_only));

        lua_createtable(L, 0, 6);
        lua_pushlstring(L, op_name.data(), op_name.size());
        lua_setfield(L, -2, "operation");
        lua_pushlstring(L, state_name.data(), state_name.size());
        lua_setfield(L, -2, "state");
        lua_pushboolean(L, cap.provider_available ? 1 : 0);
        lua_setfield(L, -2, "provider_available");
        lua_pushboolean(L, effective_can_execute ? 1 : 0);
        lua_setfield(L, -2, "can_execute");
        lua_pushlstring(L, cap.provider_name.data(), cap.provider_name.size());
        lua_setfield(L, -2, "provider_name");
        lua_pushlstring(L, cap.reason.data(), cap.reason.size());
        lua_setfield(L, -2, "reason");

        lua_pushlstring(L, op_name.data(), op_name.size());
        lua_insert(L, -2);
        lua_settable(L, -3);
    }
    return 1;
}

int lua_peelf_sections(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    const IBinaryImage* img = rt->context->image;
    if (img == nullptr) {
        lua_createtable(L, 0, 0);
        return 1;
    }
    const auto& secs = img->sections();
    lua_createtable(L, static_cast<int>(secs.size()), 0);
    for (std::size_t i = 0u; i < secs.size(); ++i) {
        const Section& s = secs[i];
        lua_createtable(L, 0, 10);
        lua_pushlstring(L, s.name.data(), s.name.size());
        lua_setfield(L, -2, "name");
        lua_pushinteger(L, static_cast<lua_Integer>(s.virtual_address));
        lua_setfield(L, -2, "va");
        lua_pushinteger(L, static_cast<lua_Integer>(s.virtual_address));
        lua_setfield(L, -2, "virtual_address");
        lua_pushinteger(L, static_cast<lua_Integer>(s.virtual_size));
        lua_setfield(L, -2, "virtual_size");
        lua_pushinteger(L, static_cast<lua_Integer>(s.file_offset));
        lua_setfield(L, -2, "file_offset");
        lua_pushinteger(L, static_cast<lua_Integer>(s.file_size));
        lua_setfield(L, -2, "file_size");
        lua_pushinteger(L, static_cast<lua_Integer>(s.raw_flags));
        lua_setfield(L, -2, "raw_flags");
        lua_pushboolean(L, s.readable ? 1 : 0);
        lua_setfield(L, -2, "readable");
        lua_pushboolean(L, s.writable ? 1 : 0);
        lua_setfield(L, -2, "writable");
        lua_pushboolean(L, s.executable ? 1 : 0);
        lua_setfield(L, -2, "executable");
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1u));
    }
    return 1;
}

int lua_peelf_segments(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    const IBinaryImage* img = rt->context->image;
    if (img == nullptr) {
        lua_createtable(L, 0, 0);
        return 1;
    }
    const auto& segs = img->segments();
    lua_createtable(L, static_cast<int>(segs.size()), 0);
    for (std::size_t i = 0u; i < segs.size(); ++i) {
        const Segment& seg = segs[i];
        lua_createtable(L, 0, 9);
        lua_pushinteger(L, static_cast<lua_Integer>(seg.type));
        lua_setfield(L, -2, "type");
        lua_pushinteger(L, static_cast<lua_Integer>(seg.virtual_address));
        lua_setfield(L, -2, "va");
        lua_pushinteger(L, static_cast<lua_Integer>(seg.virtual_address));
        lua_setfield(L, -2, "virtual_address");
        lua_pushinteger(L, static_cast<lua_Integer>(seg.virtual_size));
        lua_setfield(L, -2, "virtual_size");
        lua_pushinteger(L, static_cast<lua_Integer>(seg.file_offset));
        lua_setfield(L, -2, "file_offset");
        lua_pushinteger(L, static_cast<lua_Integer>(seg.file_size));
        lua_setfield(L, -2, "file_size");
        lua_pushboolean(L, seg.readable ? 1 : 0);
        lua_setfield(L, -2, "readable");
        lua_pushboolean(L, seg.writable ? 1 : 0);
        lua_setfield(L, -2, "writable");
        lua_pushboolean(L, seg.executable ? 1 : 0);
        lua_setfield(L, -2, "executable");
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1u));
    }
    return 1;
}

int lua_peelf_symbols(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    const IBinaryImage* img = rt->context->image;
    if (img == nullptr) {
        lua_createtable(L, 0, 0);
        return 1;
    }
    const auto& syms = img->symbols();
    lua_createtable(L, static_cast<int>(syms.size()), 0);
    for (std::size_t i = 0u; i < syms.size(); ++i) {
        const Symbol& sym = syms[i];
        lua_createtable(L, 0, 8);
        lua_pushlstring(L, sym.name.data(), sym.name.size());
        lua_setfield(L, -2, "name");
        lua_pushinteger(L, static_cast<lua_Integer>(sym.virtual_address));
        lua_setfield(L, -2, "va");
        lua_pushinteger(L, static_cast<lua_Integer>(sym.virtual_address));
        lua_setfield(L, -2, "virtual_address");
        lua_pushinteger(L, static_cast<lua_Integer>(sym.size));
        lua_setfield(L, -2, "size");
        lua_pushinteger(L, static_cast<lua_Integer>(sym.binding));
        lua_setfield(L, -2, "binding");
        lua_pushinteger(L, static_cast<lua_Integer>(sym.type));
        lua_setfield(L, -2, "type");
        lua_pushinteger(L, static_cast<lua_Integer>(sym.section_index));
        lua_setfield(L, -2, "section_index");
        lua_pushboolean(L, sym.dynamic ? 1 : 0);
        lua_setfield(L, -2, "dynamic");
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1u));
    }
    return 1;
}

int lua_peelf_imports(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    const IBinaryImage* img = rt->context->image;
    if (img == nullptr) {
        lua_createtable(L, 0, 0);
        return 1;
    }
    const auto& imps = img->imports();
    lua_createtable(L, static_cast<int>(imps.size()), 0);
    for (std::size_t i = 0u; i < imps.size(); ++i) {
        const ImportEntry& imp = imps[i];
        lua_createtable(L, 0, 7);
        lua_pushlstring(L, imp.library.data(), imp.library.size());
        lua_setfield(L, -2, "library");
        lua_pushlstring(L, imp.name.data(), imp.name.size());
        lua_setfield(L, -2, "name");
        lua_pushinteger(L, static_cast<lua_Integer>(imp.ordinal));
        lua_setfield(L, -2, "ordinal");
        lua_pushinteger(L, static_cast<lua_Integer>(imp.address));
        lua_setfield(L, -2, "va");
        lua_pushinteger(L, static_cast<lua_Integer>(imp.address));
        lua_setfield(L, -2, "address");
        lua_pushboolean(L, imp.import_by_ordinal ? 1 : 0);
        lua_setfield(L, -2, "import_by_ordinal");
        lua_pushboolean(L, imp.delay_load ? 1 : 0);
        lua_setfield(L, -2, "delay_load");
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1u));
    }
    return 1;
}

int lua_peelf_exports(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    const IBinaryImage* img = rt->context->image;
    if (img == nullptr) {
        lua_createtable(L, 0, 0);
        return 1;
    }
    const auto& exps = img->exports();
    lua_createtable(L, static_cast<int>(exps.size()), 0);
    for (std::size_t i = 0u; i < exps.size(); ++i) {
        const ExportEntry& exp = exps[i];
        lua_createtable(L, 0, 5);
        lua_pushlstring(L, exp.name.data(), exp.name.size());
        lua_setfield(L, -2, "name");
        lua_pushinteger(L, static_cast<lua_Integer>(exp.ordinal));
        lua_setfield(L, -2, "ordinal");
        lua_pushinteger(L, static_cast<lua_Integer>(exp.virtual_address));
        lua_setfield(L, -2, "va");
        lua_pushinteger(L, static_cast<lua_Integer>(exp.virtual_address));
        lua_setfield(L, -2, "virtual_address");
        lua_pushlstring(L, exp.forwarder.data(), exp.forwarder.size());
        lua_setfield(L, -2, "forwarder");
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1u));
    }
    return 1;
}

bool prepare_strings_noexcept(ScriptRuntimeState* rt, std::size_t limit) noexcept {
    try {
        rt->scratch_strings.clear();
        if (limit == 0u || rt->context->image == nullptr) {
            return true;
        }
        auto file_bytes = materialize_effective_file_bytes(*rt);
        if (!file_bytes.has_value()) {
            rt->scratch_error = file_bytes.error().message;
            return false;
        }
        rt->scratch_strings = extract_headless_strings(
            *rt->context->image, *file_bytes, 4u, limit);
        return true;
    } catch (...) {
        set_scratch_error(rt, "unexpected exception while extracting binary strings");
        return false;
    }
}

int lua_peelf_strings(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    std::size_t limit = kDefaultStringsLimit;
    if (!lua_isnoneornil(L, 1)) {
        std::uint64_t raw_limit = 0u;
        if (!parse_nonneg_u64_arg(L, 1, &raw_limit)) {
            return raise_literal_error(
                L, "bad argument #1 to 'peelf.strings' (non-negative integer expected)");
        }
        limit = static_cast<std::size_t>(
            std::min<std::uint64_t>(raw_limit, kMaxStringsLimit));
    }

    if (!prepare_strings_noexcept(rt, limit)) {
        return raise_scratch_error(L, rt);
    }

    const auto& strs = rt->scratch_strings;
    lua_createtable(L, static_cast<int>(strs.size()), 0);
    for (std::size_t i = 0u; i < strs.size(); ++i) {
        const HeadlessExtractedString& st = strs[i];
        lua_createtable(L, 0, 7);
        lua_pushlstring(L, st.value.data(), st.value.size());
        lua_setfield(L, -2, "value");
        lua_pushlstring(L, st.encoding.data(), st.encoding.size());
        lua_setfield(L, -2, "encoding");
        lua_pushlstring(L, st.section_name.data(), st.section_name.size());
        lua_setfield(L, -2, "section_name");
        lua_pushinteger(L, static_cast<lua_Integer>(st.virtual_address));
        lua_setfield(L, -2, "va");
        lua_pushinteger(L, static_cast<lua_Integer>(st.virtual_address));
        lua_setfield(L, -2, "virtual_address");
        lua_pushinteger(L, static_cast<lua_Integer>(st.file_offset));
        lua_setfield(L, -2, "file_offset");
        lua_pushinteger(L, static_cast<lua_Integer>(st.byte_length));
        lua_setfield(L, -2, "byte_length");
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1u));
    }
    return 1;
}

bool prepare_read_bytes_noexcept(ScriptRuntimeState* rt,
                                 std::uint64_t va,
                                 std::size_t len) noexcept {
    try {
        auto rd = read_effective_va_span(*rt, va, len);
        if (!rd.has_value()) {
            rt->scratch_error = rd.error().message;
            return false;
        }
        rt->scratch_bytes = std::move(*rd);
        return true;
    } catch (...) {
        set_scratch_error(rt, "unexpected exception while reading target bytes");
        return false;
    }
}

int lua_peelf_read_bytes(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    std::uint64_t va = 0u;
    std::uint64_t raw_len = 0u;
    if (!parse_va_arg(L, 1, &va)) {
        return raise_literal_error(
            L, "bad argument #1 to 'peelf.read_bytes' (integer virtual address expected)");
    }
    if (!parse_nonneg_u64_arg(L, 2, &raw_len) || raw_len > kMaxSingleReadBytes) {
        return raise_literal_error(
            L, "bad argument #2 to 'peelf.read_bytes' (length in [0, 16777216] expected)");
    }

    if (!prepare_read_bytes_noexcept(rt, va, static_cast<std::size_t>(raw_len))) {
        return raise_scratch_error(L, rt);
    }

    lua_pushlstring(
        L,
        reinterpret_cast<const char*>(rt->scratch_bytes.data()),
        rt->scratch_bytes.size());
    return 1;
}

bool prepare_read_uint_noexcept(ScriptRuntimeState* rt,
                                std::uint64_t va,
                                std::size_t width,
                                Endianness endian,
                                std::uint64_t* out_val) noexcept {
    try {
        auto rd = read_effective_va_span(*rt, va, width);
        if (!rd.has_value()) {
            rt->scratch_error = rd.error().message;
            return false;
        }
        const EndianReader reader{*rd, endian};
        switch (width) {
            case 1u: {
                const auto v = reader.read_u8(0u);
                if (!v.has_value()) {
                    rt->scratch_error = v.error().message;
                    return false;
                }
                *out_val = *v;
                return true;
            }
            case 2u: {
                const auto v = reader.read_u16(0u);
                if (!v.has_value()) {
                    rt->scratch_error = v.error().message;
                    return false;
                }
                *out_val = *v;
                return true;
            }
            case 4u: {
                const auto v = reader.read_u32(0u);
                if (!v.has_value()) {
                    rt->scratch_error = v.error().message;
                    return false;
                }
                *out_val = *v;
                return true;
            }
            case 8u: {
                const auto v = reader.read_u64(0u);
                if (!v.has_value()) {
                    rt->scratch_error = v.error().message;
                    return false;
                }
                *out_val = *v;
                return true;
            }
            default:
                rt->scratch_error = "unsupported integer width";
                return false;
        }
    } catch (...) {
        set_scratch_error(rt, "unexpected exception while reading integer");
        return false;
    }
}

template <std::size_t Width>
int lua_peelf_read_uint(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    std::uint64_t va = 0u;
    if (!parse_va_arg(L, 1, &va)) {
        return raise_literal_error(
            L, "bad argument #1 to 'peelf.read_u*' (integer virtual address expected)");
    }
    Endianness endian = target_default_endianness(*rt);
    if (!parse_optional_endianness(L, 2, endian, &endian)) {
        return raise_literal_error(
            L, "bad argument #2 to 'peelf.read_u*' ('le' or 'be' expected)");
    }
    std::uint64_t val = 0u;
    if (!prepare_read_uint_noexcept(rt, va, Width, endian, &val)) {
        return raise_scratch_error(L, rt);
    }
    lua_pushinteger(L, static_cast<lua_Integer>(val));
    return 1;
}

bool query_va_to_offset_noexcept(const ScriptRuntimeState* rt,
                                 std::uint64_t va,
                                 std::uint64_t* out_off) noexcept {
    if (rt->context->image == nullptr) {
        return false;
    }
    const auto maybe = rt->context->image->virtual_address_to_file_offset(va);
    if (!maybe.has_value()) {
        return false;
    }
    *out_off = *maybe;
    return true;
}

int lua_peelf_va_to_offset(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    std::uint64_t va = 0u;
    if (!parse_va_arg(L, 1, &va)) {
        return raise_literal_error(
            L, "bad argument #1 to 'peelf.va_to_offset' (integer virtual address expected)");
    }
    std::uint64_t off = 0u;
    if (!query_va_to_offset_noexcept(rt, va, &off)) {
        lua_pushnil(L);
        return 1;
    }
    lua_pushinteger(L, static_cast<lua_Integer>(off));
    return 1;
}

bool query_offset_to_va_noexcept(const ScriptRuntimeState* rt,
                                 std::uint64_t off,
                                 std::uint64_t* out_va) noexcept {
    if (rt->context->image == nullptr) {
        return false;
    }
    const auto maybe = rt->context->image->file_offset_to_virtual_address(off);
    if (!maybe.has_value()) {
        return false;
    }
    *out_va = *maybe;
    return true;
}

int lua_peelf_offset_to_va(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    std::uint64_t off = 0u;
    if (!parse_nonneg_u64_arg(L, 1, &off)) {
        return raise_literal_error(
            L, "bad argument #1 to 'peelf.offset_to_va' (non-negative file offset expected)");
    }
    std::uint64_t va = 0u;
    if (!query_offset_to_va_noexcept(rt, off, &va)) {
        lua_pushnil(L);
        return 1;
    }
    lua_pushinteger(L, static_cast<lua_Integer>(va));
    return 1;
}

// ---------------------------------------------------------------------------
// Disassembly (`peelf.disassemble(va, count?)`)
// ---------------------------------------------------------------------------

[[nodiscard]] bool map_capstone_arch_mode(Architecture arch,
                                          Endianness endian,
                                          cs_arch* out_arch,
                                          cs_mode* out_mode) noexcept {
    const cs_mode endian_flag =
        (endian == Endianness::Big) ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
    switch (arch) {
        case Architecture::X86:
            *out_arch = CS_ARCH_X86;
            *out_mode = CS_MODE_32;
            return true;
        case Architecture::X86_64:
            *out_arch = CS_ARCH_X86;
            *out_mode = CS_MODE_64;
            return true;
        case Architecture::ARM:
            *out_arch = CS_ARCH_ARM;
            *out_mode = static_cast<cs_mode>(CS_MODE_ARM | endian_flag);
            return true;
        case Architecture::ARM64:
            *out_arch = CS_ARCH_ARM64;
            *out_mode = endian_flag;
            return true;
        case Architecture::MIPS32:
            *out_arch = CS_ARCH_MIPS;
            *out_mode = static_cast<cs_mode>(CS_MODE_MIPS32 | endian_flag);
            return true;
        case Architecture::MIPS64:
            *out_arch = CS_ARCH_MIPS;
            *out_mode = static_cast<cs_mode>(CS_MODE_MIPS64 | endian_flag);
            return true;
        case Architecture::PowerPC:
            *out_arch = CS_ARCH_PPC;
            *out_mode = endian_flag;
            return true;
        case Architecture::PowerPC64:
            *out_arch = CS_ARCH_PPC;
            *out_mode = static_cast<cs_mode>(CS_MODE_64 | endian_flag);
            return true;
        case Architecture::RISCV32:
            *out_arch = CS_ARCH_RISCV;
            *out_mode = static_cast<cs_mode>(CS_MODE_RISCV32 | CS_MODE_RISCVC);
            return true;
        case Architecture::RISCV64:
            *out_arch = CS_ARCH_RISCV;
            *out_mode = static_cast<cs_mode>(CS_MODE_RISCV64 | CS_MODE_RISCVC);
            return true;
        case Architecture::Unknown:
            return false;
    }
    return false;
}

[[nodiscard]] std::size_t probe_readable_disasm_window(const ScriptRuntimeState& rt,
                                                       std::uint64_t va,
                                                       std::size_t max_bytes) {
    if (max_bytes == 0u) {
        return 0u;
    }
    // Fast path: try full window first.
    if (read_effective_va_span(rt, va, max_bytes).has_value()) {
        return max_bytes;
    }
    // Binary-search exact contiguous mapped prefix starting at `va` (handles small sections).
    std::size_t lo = 0u;
    std::size_t hi = max_bytes;
    while (lo < hi) {
        const std::size_t mid = lo + ((hi - lo + 1u) / 2u);
        if (read_effective_va_span(rt, va, mid).has_value()) {
            lo = mid;
        } else {
            hi = mid - 1u;
        }
    }
    return lo;
}

bool prepare_disassemble_noexcept(ScriptRuntimeState* rt,
                                  std::uint64_t va,
                                  std::size_t count) noexcept {
    try {
        rt->scratch_disasm.clear();
        const Capability& cap = rt->capabilities[Operation::Disassembly];
        if (!cap.can_execute()) {
            rt->scratch_error = std::format(
                "Disassembly capability is unavailable for target: {}", cap.reason);
            return false;
        }

        Architecture arch = rt->capabilities.profile().architecture;
        Endianness endian = rt->capabilities.profile().endianness;
        if (rt->context->image != nullptr) {
            arch = rt->context->image->architecture();
            endian = rt->context->image->endianness();
        } else if (IProcessSession* sess = active_process_session(*rt->context);
                   sess != nullptr) {
            arch = sess->info().architecture;
            endian = sess->info().endianness;
        }

        cs_arch cs_architecture{};
        cs_mode cs_mode_flags{};
        if (!map_capstone_arch_mode(arch, endian, &cs_architecture, &cs_mode_flags)) {
            rt->scratch_error = "unsupported target architecture for Capstone disassembly";
            return false;
        }

        const std::size_t max_window = std::min<std::size_t>(count * 16u, 65536u);
        const std::size_t readable = probe_readable_disasm_window(*rt, va, max_window);
        if (readable == 0u) {
            rt->scratch_error = std::format(
                "virtual address 0x{:x} is not mapped for disassembly", va);
            return false;
        }
        auto code_bytes = read_effective_va_span(*rt, va, readable);
        if (!code_bytes.has_value()) {
            rt->scratch_error = code_bytes.error().message;
            return false;
        }

        ScopedCapstoneHandle handle{};
        if (cs_open(cs_architecture, cs_mode_flags, handle.put()) != CS_ERR_OK) {
            rt->scratch_error = "failed to initialize Capstone disassembler handle";
            return false;
        }

        cs_insn* raw_insns = nullptr;
        const std::size_t decoded = cs_disasm(
            handle.get(),
            code_bytes->data(),
            code_bytes->size(),
            va,
            count,
            &raw_insns);
        const ScopedCapstoneInsns guard{raw_insns, decoded};

        rt->scratch_disasm.reserve(decoded);
        for (std::size_t i = 0u; i < decoded; ++i) {
            const cs_insn& insn = raw_insns[i];
            ScratchDisasmItem item{};
            item.address = insn.address;
            item.bytes.assign(insn.bytes, insn.bytes + insn.size);
            item.mnemonic = insn.mnemonic;
            item.operands = insn.op_str;
            item.text = item.operands.empty()
                ? item.mnemonic
                : (item.mnemonic + " " + item.operands);
            rt->scratch_disasm.push_back(std::move(item));
        }
        return true;
    } catch (...) {
        set_scratch_error(rt, "unexpected exception during disassembly");
        return false;
    }
}

int lua_peelf_disassemble(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    std::uint64_t va = 0u;
    if (!parse_va_arg(L, 1, &va)) {
        return raise_literal_error(
            L, "bad argument #1 to 'peelf.disassemble' (integer virtual address expected)");
    }
    std::size_t count = kDefaultDisasmCount;
    if (!lua_isnoneornil(L, 2)) {
        std::uint64_t raw_count = 0u;
        if (!parse_nonneg_u64_arg(L, 2, &raw_count) || raw_count == 0u ||
            raw_count > kMaxDisasmCount) {
            return raise_literal_error(
                L, "bad argument #2 to 'peelf.disassemble' (count in [1, 4096] expected)");
        }
        count = static_cast<std::size_t>(raw_count);
    }

    if (!prepare_disassemble_noexcept(rt, va, count)) {
        return raise_scratch_error(L, rt);
    }

    const auto& items = rt->scratch_disasm;
    lua_createtable(L, static_cast<int>(items.size()), 0);
    for (std::size_t i = 0u; i < items.size(); ++i) {
        const ScratchDisasmItem& ins = items[i];
        lua_createtable(L, 0, 7);
        lua_pushinteger(L, static_cast<lua_Integer>(ins.address));
        lua_setfield(L, -2, "va");
        lua_pushinteger(L, static_cast<lua_Integer>(ins.address));
        lua_setfield(L, -2, "address");
        lua_pushinteger(L, static_cast<lua_Integer>(ins.bytes.size()));
        lua_setfield(L, -2, "size");
        lua_pushlstring(
            L,
            reinterpret_cast<const char*>(ins.bytes.data()),
            ins.bytes.size());
        lua_setfield(L, -2, "bytes");
        lua_pushlstring(L, ins.mnemonic.data(), ins.mnemonic.size());
        lua_setfield(L, -2, "mnemonic");
        lua_pushlstring(L, ins.operands.data(), ins.operands.size());
        lua_setfield(L, -2, "operands");
        lua_pushlstring(L, ins.text.data(), ins.text.size());
        lua_setfield(L, -2, "text");
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1u));
    }
    return 1;
}

// ---------------------------------------------------------------------------
// Security audit (`peelf.security_audit()`)
// ---------------------------------------------------------------------------

bool prepare_security_audit_noexcept(ScriptRuntimeState* rt) noexcept {
    try {
        const Capability& cap = rt->capabilities[Operation::SecurityAudit];
        if (!cap.can_execute()) {
            rt->scratch_error = std::format(
                "SecurityAudit capability is unavailable for target: {}", cap.reason);
            return false;
        }

        IProcessSession* sess = active_process_session(*rt->context);
        if (rt->context->image != nullptr) {
            std::vector<std::uint8_t> effective_bytes{};
            if (auto mb = materialize_effective_file_bytes(*rt); mb.has_value()) {
                effective_bytes = std::move(*mb);
            }
            rt->scratch_audit = audit_security(*rt->context->image, effective_bytes, sess);
            return true;
        }
        if (sess != nullptr) {
            rt->scratch_audit = audit_live_process_security(*sess);
            return true;
        }
        rt->scratch_error = "no binary image or live session available for security_audit";
        return false;
    } catch (...) {
        set_scratch_error(rt, "unexpected exception during security audit");
        return false;
    }
}

int lua_peelf_security_audit(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    if (!prepare_security_audit_noexcept(rt)) {
        return raise_scratch_error(L, rt);
    }

    const SecurityAuditReport& rep = rt->scratch_audit;
    const std::string_view fmt_str = to_string(rep.target_format);

    lua_createtable(L, 0, 7);
    lua_pushlstring(L, fmt_str.data(), fmt_str.size());
    lua_setfield(L, -2, "format");
    lua_pushboolean(L, rep.includes_live_process ? 1 : 0);
    lua_setfield(L, -2, "includes_live_process");
    lua_pushinteger(L, static_cast<lua_Integer>(rep.pass_count));
    lua_setfield(L, -2, "pass_count");
    lua_pushinteger(L, static_cast<lua_Integer>(rep.note_count));
    lua_setfield(L, -2, "note_count");
    lua_pushinteger(L, static_cast<lua_Integer>(rep.warning_count));
    lua_setfield(L, -2, "warning_count");
    lua_pushinteger(L, static_cast<lua_Integer>(rep.error_count));
    lua_setfield(L, -2, "error_count");

    lua_createtable(L, static_cast<int>(rep.findings.size()), 0);
    for (std::size_t i = 0u; i < rep.findings.size(); ++i) {
        const SecurityFinding& f = rep.findings[i];
        const std::string_view dom_str = to_string(f.domain);
        const std::string_view sev_str = to_string(f.severity);

        lua_createtable(L, 0, 11);
        lua_pushlstring(L, f.rule_id.data(), f.rule_id.size());
        lua_setfield(L, -2, "rule_id");
        lua_pushlstring(L, f.rule_name.data(), f.rule_name.size());
        lua_setfield(L, -2, "rule_name");
        lua_pushlstring(L, dom_str.data(), dom_str.size());
        lua_setfield(L, -2, "domain");
        lua_pushlstring(L, sev_str.data(), sev_str.size());
        lua_setfield(L, -2, "severity");
        lua_pushlstring(L, f.subject.data(), f.subject.size());
        lua_setfield(L, -2, "subject");
        lua_pushlstring(L, f.summary.data(), f.summary.size());
        lua_setfield(L, -2, "summary");
        lua_pushlstring(L, f.evidence.data(), f.evidence.size());
        lua_setfield(L, -2, "evidence");
        lua_pushlstring(L, f.remediation.data(), f.remediation.size());
        lua_setfield(L, -2, "remediation");
        if (f.virtual_address.has_value()) {
            lua_pushinteger(L, static_cast<lua_Integer>(*f.virtual_address));
            lua_setfield(L, -2, "va");
            lua_pushinteger(L, static_cast<lua_Integer>(*f.virtual_address));
            lua_setfield(L, -2, "virtual_address");
        }
        if (f.file_offset.has_value()) {
            lua_pushinteger(L, static_cast<lua_Integer>(*f.file_offset));
            lua_setfield(L, -2, "file_offset");
        }
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1u));
    }
    lua_setfield(L, -2, "findings");
    return 1;
}

// ---------------------------------------------------------------------------
// Transactional annotation, patch staging, commit, and rollback bindings
// ---------------------------------------------------------------------------

bool stage_label_noexcept(ScriptRuntimeState* rt,
                          std::uint64_t va,
                          const char* ptr,
                          std::size_t len) noexcept {
    if (!verify_mutation_allowed_noexcept(rt, false)) {
        return false;
    }
    try {
        rt->transaction.stage_label(va, std::string{ptr, len});
        return true;
    } catch (...) {
        set_scratch_error(rt, "out of memory while staging label");
        return false;
    }
}

int lua_peelf_set_label(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    std::uint64_t va = 0u;
    if (!parse_va_arg(L, 1, &va)) {
        return raise_literal_error(
            L, "bad argument #1 to 'peelf.set_label' (integer virtual address expected)");
    }
    if (lua_type(L, 2) != LUA_TSTRING) {
        return raise_literal_error(
            L, "bad argument #2 to 'peelf.set_label' (string label expected)");
    }
    std::size_t len = 0u;
    const char* ptr = lua_tolstring(L, 2, &len);
    if (!stage_label_noexcept(rt, va, ptr, len)) {
        return raise_scratch_error(L, rt);
    }
    return 0;
}

bool get_label_noexcept(ScriptRuntimeState* rt,
                        std::uint64_t va,
                        bool* out_present) noexcept {
    try {
        const auto lbl = rt->transaction.effective_label(va);
        if (!lbl.has_value()) {
            *out_present = false;
            return true;
        }
        rt->scratch_text = *lbl;
        *out_present = true;
        return true;
    } catch (...) {
        set_scratch_error(rt, "unexpected exception reading label");
        return false;
    }
}

int lua_peelf_get_label(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    std::uint64_t va = 0u;
    if (!parse_va_arg(L, 1, &va)) {
        return raise_literal_error(
            L, "bad argument #1 to 'peelf.get_label' (integer virtual address expected)");
    }
    bool present = false;
    if (!get_label_noexcept(rt, va, &present)) {
        return raise_scratch_error(L, rt);
    }
    if (!present) {
        lua_pushnil(L);
        return 1;
    }
    lua_pushlstring(L, rt->scratch_text.data(), rt->scratch_text.size());
    return 1;
}

bool stage_comment_noexcept(ScriptRuntimeState* rt,
                            std::uint64_t va,
                            const char* ptr,
                            std::size_t len) noexcept {
    if (!verify_mutation_allowed_noexcept(rt, false)) {
        return false;
    }
    try {
        rt->transaction.stage_comment(va, std::string{ptr, len});
        return true;
    } catch (...) {
        set_scratch_error(rt, "out of memory while staging comment");
        return false;
    }
}

int lua_peelf_set_comment(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    std::uint64_t va = 0u;
    if (!parse_va_arg(L, 1, &va)) {
        return raise_literal_error(
            L, "bad argument #1 to 'peelf.set_comment' (integer virtual address expected)");
    }
    if (lua_type(L, 2) != LUA_TSTRING) {
        return raise_literal_error(
            L, "bad argument #2 to 'peelf.set_comment' (string comment expected)");
    }
    std::size_t len = 0u;
    const char* ptr = lua_tolstring(L, 2, &len);
    if (!stage_comment_noexcept(rt, va, ptr, len)) {
        return raise_scratch_error(L, rt);
    }
    return 0;
}

bool get_comment_noexcept(ScriptRuntimeState* rt,
                          std::uint64_t va,
                          bool* out_present) noexcept {
    try {
        const auto cmt = rt->transaction.effective_comment(va);
        if (!cmt.has_value()) {
            *out_present = false;
            return true;
        }
        rt->scratch_text = *cmt;
        *out_present = true;
        return true;
    } catch (...) {
        set_scratch_error(rt, "unexpected exception reading comment");
        return false;
    }
}

int lua_peelf_get_comment(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    std::uint64_t va = 0u;
    if (!parse_va_arg(L, 1, &va)) {
        return raise_literal_error(
            L, "bad argument #1 to 'peelf.get_comment' (integer virtual address expected)");
    }
    bool present = false;
    if (!get_comment_noexcept(rt, va, &present)) {
        return raise_scratch_error(L, rt);
    }
    if (!present) {
        lua_pushnil(L);
        return 1;
    }
    lua_pushlstring(L, rt->scratch_text.data(), rt->scratch_text.size());
    return 1;
}

bool add_bookmark_noexcept(ScriptRuntimeState* rt,
                           std::uint64_t va,
                           const char* ptr,
                           std::size_t len) noexcept {
    if (!verify_mutation_allowed_noexcept(rt, false)) {
        return false;
    }
    try {
        rt->transaction.stage_bookmark(va, std::string{ptr, len});
        return true;
    } catch (...) {
        set_scratch_error(rt, "out of memory while staging bookmark");
        return false;
    }
}

int lua_peelf_add_bookmark(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    std::uint64_t va = 0u;
    if (!parse_va_arg(L, 1, &va)) {
        return raise_literal_error(
            L, "bad argument #1 to 'peelf.add_bookmark' (integer virtual address expected)");
    }
    if (lua_type(L, 2) != LUA_TSTRING) {
        return raise_literal_error(
            L, "bad argument #2 to 'peelf.add_bookmark' (string label expected)");
    }
    std::size_t len = 0u;
    const char* ptr = lua_tolstring(L, 2, &len);
    if (!add_bookmark_noexcept(rt, va, ptr, len)) {
        return raise_scratch_error(L, rt);
    }
    return 0;
}

int lua_peelf_bookmarks(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    const auto bms = rt->transaction.effective_bookmarks();
    lua_createtable(L, static_cast<int>(bms.size()), 0);
    for (std::size_t i = 0u; i < bms.size(); ++i) {
        const ScriptBookmark& bm = bms[i];
        lua_createtable(L, 0, 4);
        lua_pushinteger(L, static_cast<lua_Integer>(bm.virtual_address));
        lua_setfield(L, -2, "va");
        lua_pushinteger(L, static_cast<lua_Integer>(bm.virtual_address));
        lua_setfield(L, -2, "address");
        lua_pushinteger(L, static_cast<lua_Integer>(bm.virtual_address));
        lua_setfield(L, -2, "virtual_address");
        lua_pushlstring(L, bm.label.data(), bm.label.size());
        lua_setfield(L, -2, "label");
        lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1u));
    }
    return 1;
}

bool prepare_scratch_patch_buffer_noexcept(ScriptRuntimeState* rt,
                                           std::size_t count) noexcept {
    try {
        rt->scratch_bytes.assign(count, 0u);
        return true;
    } catch (...) {
        set_scratch_error(rt, "out of memory preparing patch byte buffer");
        return false;
    }
}

bool stage_patch_bytes_noexcept(ScriptRuntimeState* rt,
                                std::uint64_t va,
                                const std::uint8_t* bytes,
                                std::size_t len) noexcept {
    if (!verify_mutation_allowed_noexcept(rt, true)) {
        return false;
    }
    try {
        if (len == 0u) {
            rt->scratch_error = "peelf.stage_patch requires at least 1 byte";
            return false;
        }
        if (len > kMaxSingleReadBytes) {
            rt->scratch_error = "peelf.stage_patch length exceeds 16 MiB sandbox limit";
            return false;
        }
        if (!checked_add(va, static_cast<std::uint64_t>(len)).has_value()) {
            rt->scratch_error = "peelf.stage_patch virtual address range overflows 64-bit space";
            return false;
        }

        const ScriptContext& ctx = *rt->context;
        if (ctx.image == nullptr) {
            rt->scratch_error = "peelf.stage_patch requires a parsed static IBinaryImage";
            return false;
        }

        const auto maybe_backing_size = static_backing_size(ctx);

        // Two-pass validation so a multi-byte patch either stages completely or fails cleanly
        // before mutating `ScriptTransaction`.
        struct ValidatedCell {
            std::uint64_t file_offset{0};
            std::uint64_t virtual_address{0};
            std::uint8_t baseline{0};
            std::uint8_t replacement{0};
        };
        std::vector<ValidatedCell> validated;
        validated.reserve(len);

        for (std::size_t i = 0u; i < len; ++i) {
            const std::uint64_t cur_va = va + static_cast<std::uint64_t>(i);
            const auto maybe_off = ctx.image->virtual_address_to_file_offset(cur_va);
            if (!maybe_off.has_value()) {
                rt->scratch_error = std::format(
                    "virtual address 0x{:x} does not map to a file-backed static section/segment",
                    cur_va);
                return false;
            }
            const std::uint64_t file_off = *maybe_off;
            if (!ctx.image->slice_relative_offset(file_off).has_value()) {
                rt->scratch_error = std::format(
                    "file offset 0x{:x} lies outside the active container slice bounds",
                    file_off);
                return false;
            }
            if (maybe_backing_size.has_value() && file_off >= *maybe_backing_size) {
                rt->scratch_error = std::format(
                    "file offset 0x{:x} exceeds backing binary size ({} bytes)",
                    file_off, *maybe_backing_size);
                return false;
            }
            auto orig_byte = read_baseline_static_byte(ctx, file_off);
            if (!orig_byte.has_value()) {
                rt->scratch_error = orig_byte.error().message;
                return false;
            }
            validated.push_back(ValidatedCell{
                .file_offset = file_off,
                .virtual_address = cur_va,
                .baseline = *orig_byte,
                .replacement = bytes[i],
            });
        }

        for (const ValidatedCell& cell : validated) {
            rt->transaction.stage_byte(
                cell.file_offset,
                cell.virtual_address,
                cell.baseline,
                cell.replacement);
        }
        return true;
    } catch (...) {
        set_scratch_error(rt, "unexpected exception while staging patch");
        return false;
    }
}

int lua_peelf_stage_patch(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    std::uint64_t va = 0u;
    if (!parse_va_arg(L, 1, &va)) {
        return raise_literal_error(
            L, "bad argument #1 to 'peelf.stage_patch' (integer virtual address expected)");
    }

    const int arg2_type = lua_type(L, 2);
    if (arg2_type == LUA_TSTRING) {
        std::size_t len = 0u;
        const char* ptr = lua_tolstring(L, 2, &len);
        if (!stage_patch_bytes_noexcept(
                rt, va, reinterpret_cast<const std::uint8_t*>(ptr), len)) {
            return raise_scratch_error(L, rt);
        }
        return 0;
    }

    if (arg2_type == LUA_TTABLE) {
        const lua_Unsigned raw_len = lua_rawlen(L, 2);
        if (raw_len == 0u || raw_len > kMaxSingleReadBytes) {
            return raise_literal_error(
                L,
                "bad argument #2 to 'peelf.stage_patch' (non-empty byte table <= 16 MiB expected)");
        }
        const auto count = static_cast<std::size_t>(raw_len);
        if (!prepare_scratch_patch_buffer_noexcept(rt, count)) {
            return raise_scratch_error(L, rt);
        }
        for (std::size_t i = 0u; i < count; ++i) {
            lua_rawgeti(L, 2, static_cast<lua_Integer>(i + 1u));
            int is_int = 0;
            const lua_Integer bval = lua_tointegerx(L, -1, &is_int);
            lua_pop(L, 1);
            if (is_int == 0 || bval < 0 || bval > 255) {
                return raise_literal_error(
                    L,
                    "bad byte element in 'peelf.stage_patch' table (integer in [0, 255] expected)");
            }
            rt->scratch_bytes[i] = static_cast<std::uint8_t>(bval);
        }
        if (!stage_patch_bytes_noexcept(
                rt, va, rt->scratch_bytes.data(), rt->scratch_bytes.size())) {
            return raise_scratch_error(L, rt);
        }
        return 0;
    }

    return raise_literal_error(
        L, "bad argument #2 to 'peelf.stage_patch' (byte string or byte table expected)");
}

bool request_commit_noexcept(ScriptRuntimeState* rt,
                             const char* label_ptr,
                             std::size_t label_len) noexcept {
    const bool needs_static_patching = rt->transaction.has_staged_patches();
    if (!verify_mutation_allowed_noexcept(rt, needs_static_patching)) {
        return false;
    }
    try {
        if (rt->transaction.has_staged_patches() && rt->context->paged_image == nullptr) {
            rt->scratch_error =
                "cannot commit staged byte patches: ScriptContext has no PagedBinaryImage";
            return false;
        }
        if (rt->transaction.has_staged_annotations() && rt->context->workspace == nullptr) {
            rt->scratch_error =
                "cannot commit staged annotations: ScriptContext has no ProjectWorkspace";
            return false;
        }
        if (label_ptr != nullptr && label_len > 0u) {
            rt->transaction.request_commit(std::string{label_ptr, label_len});
        } else {
            rt->transaction.request_commit();
        }
        return true;
    } catch (...) {
        set_scratch_error(rt, "unexpected exception requesting script commit");
        return false;
    }
}

int lua_peelf_commit(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    const char* label_ptr = nullptr;
    std::size_t label_len = 0u;
    if (!lua_isnoneornil(L, 1)) {
        if (lua_type(L, 1) != LUA_TSTRING) {
            return raise_literal_error(
                L, "bad argument #1 to 'peelf.commit' (optional string label expected)");
        }
        label_ptr = lua_tolstring(L, 1, &label_len);
    }
    if (!request_commit_noexcept(rt, label_ptr, label_len)) {
        return raise_scratch_error(L, rt);
    }
    lua_pushboolean(L, 1);
    return 1;
}

bool rollback_noexcept(ScriptRuntimeState* rt) noexcept {
    try {
        rt->transaction.rollback();
        return true;
    } catch (...) {
        set_scratch_error(rt, "unexpected exception rolling back script transaction");
        return false;
    }
}

int lua_peelf_rollback(lua_State* L) {
    auto* rt = get_runtime_upvalue(L);
    if (!rollback_noexcept(rt)) {
        return raise_scratch_error(L, rt);
    }
    lua_pushboolean(L, 1);
    return 1;
}

// ---------------------------------------------------------------------------
// Protected Lua VM bootstrap (`pmain`)
// ---------------------------------------------------------------------------

void register_peelf_fn(lua_State* L,
                       ScriptRuntimeState* rt,
                       const char* name,
                       lua_CFunction fn) {
    lua_pushlightuserdata(L, rt);
    lua_pushcclosure(L, fn, 1);
    lua_setfield(L, -2, name);
}

int lua_protected_main(lua_State* L) {
    auto* rt = static_cast<ScriptRuntimeState*>(lua_touserdata(L, 1));

    // 1. Load strictly the safe standard library subset.
    luaL_requiref(L, LUA_GNAME, luaopen_base, 1);
    lua_pop(L, 1);
    luaL_requiref(L, LUA_TABLIBNAME, luaopen_table, 1);
    lua_pop(L, 1);
    luaL_requiref(L, LUA_STRLIBNAME, luaopen_string, 1);
    lua_pop(L, 1);
    luaL_requiref(L, LUA_MATHLIBNAME, luaopen_math, 1);
    lua_pop(L, 1);
    luaL_requiref(L, LUA_UTF8LIBNAME, luaopen_utf8, 1);
    lua_pop(L, 1);

    // 2. Strip filesystem, OS, debug, package/require, and stderr warning globals.
    constexpr std::array<const char*, 8> kForbiddenGlobals = {
        "dofile",
        "loadfile",
        "io",
        "os",
        "debug",
        "package",
        "require",
        "warn",
    };
    for (const char* name : kForbiddenGlobals) {
        lua_pushnil(L);
        lua_setglobal(L, name);
    }

    // 3. Install hermetic replacements for `print`, `load`, `pcall`, and `xpcall`.
    lua_pushlightuserdata(L, rt);
    lua_pushcclosure(L, &lua_sandbox_print, 1);
    lua_setglobal(L, "print");

    lua_pushcfunction(L, &lua_sandbox_load);
    lua_setglobal(L, "load");

    lua_pushlightuserdata(L, rt);
    lua_pushcclosure(L, &lua_sandbox_pcall, 1);
    lua_setglobal(L, "pcall");

    lua_pushlightuserdata(L, rt);
    lua_pushcclosure(L, &lua_sandbox_xpcall, 1);
    lua_setglobal(L, "xpcall");

    // 4. Register `peelf` module table.
    lua_createtable(L, 0, 24);
    register_peelf_fn(L, rt, "log", &lua_sandbox_print);
    register_peelf_fn(L, rt, "target_info", &lua_peelf_target_info);
    register_peelf_fn(L, rt, "capabilities", &lua_peelf_capabilities);
    register_peelf_fn(L, rt, "sections", &lua_peelf_sections);
    register_peelf_fn(L, rt, "segments", &lua_peelf_segments);
    register_peelf_fn(L, rt, "symbols", &lua_peelf_symbols);
    register_peelf_fn(L, rt, "imports", &lua_peelf_imports);
    register_peelf_fn(L, rt, "exports", &lua_peelf_exports);
    register_peelf_fn(L, rt, "strings", &lua_peelf_strings);
    register_peelf_fn(L, rt, "read_bytes", &lua_peelf_read_bytes);
    register_peelf_fn(L, rt, "read_u8", &lua_peelf_read_uint<1u>);
    register_peelf_fn(L, rt, "read_u16", &lua_peelf_read_uint<2u>);
    register_peelf_fn(L, rt, "read_u32", &lua_peelf_read_uint<4u>);
    register_peelf_fn(L, rt, "read_u64", &lua_peelf_read_uint<8u>);
    register_peelf_fn(L, rt, "va_to_offset", &lua_peelf_va_to_offset);
    register_peelf_fn(L, rt, "offset_to_va", &lua_peelf_offset_to_va);
    register_peelf_fn(L, rt, "disassemble", &lua_peelf_disassemble);
    register_peelf_fn(L, rt, "security_audit", &lua_peelf_security_audit);
    register_peelf_fn(L, rt, "set_label", &lua_peelf_set_label);
    register_peelf_fn(L, rt, "get_label", &lua_peelf_get_label);
    register_peelf_fn(L, rt, "set_comment", &lua_peelf_set_comment);
    register_peelf_fn(L, rt, "get_comment", &lua_peelf_get_comment);
    register_peelf_fn(L, rt, "add_bookmark", &lua_peelf_add_bookmark);
    register_peelf_fn(L, rt, "bookmarks", &lua_peelf_bookmarks);
    register_peelf_fn(L, rt, "stage_patch", &lua_peelf_stage_patch);
    register_peelf_fn(L, rt, "commit", &lua_peelf_commit);
    register_peelf_fn(L, rt, "rollback", &lua_peelf_rollback);
    lua_setglobal(L, "peelf");

    // 5. Reject precompiled binary Lua bytecode (`\x1bLua`) and load text-only chunk.
    if (!rt->script_source.empty() && rt->script_source[0] == '\x1b') {
        rt->load_error_kind = ScriptErrorKind::SyntaxOrLoadError;
        lua_pushliteral(L, "sandbox forbids binary Lua bytecode chunks (text mode 't' only)");
        lua_error(L);
        std::unreachable();
    }

    const int load_rc = luaL_loadbufferx(
        L,
        rt->script_source.data(),
        rt->script_source.size(),
        rt->chunk_label.c_str(),
        "t");
    if (load_rc != LUA_OK) {
        if (load_rc != LUA_ERRMEM) {
            rt->load_error_kind = ScriptErrorKind::SyntaxOrLoadError;
        }
        lua_error(L);
        std::unreachable();
    }

    // 6. Arm instruction / timeout / stop_token hook and execute chunk.
    lua_sethook(L, &sandbox_instruction_hook, LUA_MASKCOUNT, rt->hook_step);
    lua_call(L, 0, 0);
    return 0;
}

} // namespace

// ---------------------------------------------------------------------------
// LuaScriptingEngine::execute
// ---------------------------------------------------------------------------

ScriptExecutionResult LuaScriptingEngine::execute(
    std::string_view script_source,
    ScriptContext& context,
    const ScriptLimits& limits,
    std::stop_token stop_token,
    std::string_view chunk_name) const {
    const auto start = std::chrono::steady_clock::now();
    ScriptExecutionResult result{};

    if (stop_token.stop_requested()) {
        result.ok = false;
        result.error_kind = ScriptErrorKind::Cancelled;
        result.error_message = "script cancelled via stop_token before start";
        return result;
    }

    if (limits.max_memory_bytes == 0u) {
        result.ok = false;
        result.error_kind = ScriptErrorKind::MemoryLimitExceeded;
        result.error_message = "script max_memory_bytes quota is 0";
        return result;
    }

    if (limits.max_instructions == 0u) {
        result.ok = false;
        result.error_kind = ScriptErrorKind::InstructionLimitExceeded;
        result.error_message = "script max_instructions quota is 0";
        return result;
    }

    if (limits.wall_clock_timeout.count() <= 0) {
        result.ok = false;
        result.error_kind = ScriptErrorKind::WallClockTimeout;
        result.error_message = "script wall_clock_timeout quota is non-positive";
        return result;
    }

    ScriptRuntimeState rt{};
    rt.context = &context;
    rt.limits = limits;
    rt.stop_token = std::move(stop_token);
    rt.start_time = start;
    rt.hook_step = static_cast<int>(
        std::clamp<std::uint64_t>(limits.max_instructions, 1u, 256u));
    rt.script_source = script_source;
    rt.chunk_label = chunk_name.empty()
        ? std::string{"@script.lua"}
        : (chunk_name.starts_with('@') || chunk_name.starts_with('=')
               ? std::string{chunk_name}
               : ("@" + std::string{chunk_name}));
    rt.enforce_memory_quota = true;
    rt.fatal_abort_message.reserve(256u);
    rt.scratch_error.reserve(256u);
    rt.transaction.reset(context.workspace);

    IProcessSession* active_session = active_process_session(context);
    if (context.capabilities.has_value()) {
        rt.capabilities = *context.capabilities;
    } else {
        const TargetProfile profile = derive_target_profile(
            context.image, active_session, false, context.remote_gdb_rsp);
        rt.capabilities = capabilities_for(profile, ProviderFacts::detect_host_providers());
    }
    rt.effective_read_only =
        context.is_read_only ||
        active_session != nullptr ||
        context.remote_gdb_rsp ||
        (rt.capabilities.profile().backend != BackendKind::StaticFile);

    UniqueLuaState state{lua_newstate(&sandbox_lua_alloc, &rt)};
    if (!state) {
        result.ok = false;
        result.error_kind = rt.memory_limit_exceeded
            ? ScriptErrorKind::MemoryLimitExceeded
            : ScriptErrorKind::RuntimeError;
        result.error_message = rt.memory_limit_exceeded
            ? std::format("script exceeded max_memory_bytes quota ({} bytes) during VM init",
                          limits.max_memory_bytes)
            : "failed to allocate Lua 5.4 state";
        result.peak_memory_bytes = rt.peak_memory_bytes;
        result.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        return result;
    }

    lua_atpanic(state.get(), &sandbox_panic_handler);
    lua_pushcfunction(state.get(), &lua_protected_main);
    lua_pushlightuserdata(state.get(), &rt);
    const int pcall_rc = lua_pcall(state.get(), 1, 0, 0);

    std::string vm_err{};
    if (pcall_rc != LUA_OK && lua_type(state.get(), -1) == LUA_TSTRING) {
        std::size_t elen = 0u;
        const char* eptr = lua_tolstring(state.get(), -1, &elen);
        if (eptr != nullptr && elen > 0u) {
            vm_err.assign(eptr, elen);
        }
    }

    // Close the Lua VM before touching host state so all Lua allocations are released cleanly.
    state.reset();

    result.output = std::move(rt.output);
    result.output_truncated = rt.output_truncated;
    result.instructions_executed = rt.instructions_executed;
    result.peak_memory_bytes = rt.peak_memory_bytes;
    result.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start);

    if (pcall_rc != LUA_OK) {
        // Automatic rollback: zero staged mutations touch `PagedBinaryImage` or `ProjectWorkspace`.
        result.ok = false;
        result.committed = false;
        if (rt.fatal_abort_kind != ScriptErrorKind::None) {
            result.error_kind = rt.fatal_abort_kind;
            result.error_message = !rt.fatal_abort_message.empty()
                ? rt.fatal_abort_message
                : vm_err;
        } else if (pcall_rc == LUA_ERRMEM || rt.memory_limit_exceeded) {
            result.error_kind = ScriptErrorKind::MemoryLimitExceeded;
            result.error_message = !vm_err.empty()
                ? vm_err
                : std::format("script exceeded max_memory_bytes quota ({} bytes)",
                              limits.max_memory_bytes);
        } else if (rt.load_error_kind != ScriptErrorKind::None) {
            result.error_kind = rt.load_error_kind;
            result.error_message = !vm_err.empty() ? vm_err : "Lua syntax or chunk load error";
        } else {
            result.error_kind = ScriptErrorKind::RuntimeError;
            result.error_message = !vm_err.empty() ? vm_err : "Lua runtime error";
        }
        return result;
    }

    // Capture staged preview summary (available on both dry-run and committed runs).
    result.staged_summary.staged_patches = rt.transaction.coalesced_patches();
    result.staged_summary.staged_labels = rt.transaction.staged_labels();
    result.staged_summary.staged_comments = rt.transaction.staged_comments();
    {
        const auto bms = rt.transaction.effective_bookmarks();
        result.staged_summary.staged_bookmarks.assign(bms.begin(), bms.end());
    }
    result.staged_summary.bookmarks_modified = rt.transaction.has_staged_annotations() &&
        (!rt.transaction.effective_bookmarks().empty() || context.workspace != nullptr);

    if (!rt.transaction.commit_requested()) {
        // Clean exit without `peelf.commit()` -> dry-run only (`committed == false`).
        result.ok = true;
        result.committed = false;
        return result;
    }

    // Apply all staged patches and workspace annotations atomically at the host boundary.
    if (auto applied = rt.transaction.apply_to_host(context.paged_image, context.workspace);
        !applied.has_value()) {
        result.ok = false;
        result.committed = false;
        result.error_kind = ScriptErrorKind::CommitFailed;
        result.error_message = applied.error().message;
        return result;
    }

    result.ok = true;
    result.committed = true;
    return result;
}

} // namespace peelf
