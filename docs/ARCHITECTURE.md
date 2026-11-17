# PE / ELF Explorer Architecture

This document describes the post-`89cf67f` runtime and build architecture of PE / ELF Explorer across its three primary CMake targets (`peelf_core`, `peelf_gui`, and `peelf_viewer`). Related documents:
- **[User Guide (`docs/USER_GUIDE.md`)](USER_GUIDE.md)** — End-to-end feature walkthrough, UI panels, shortcuts, and CLI automation
- **[Roadmap & C++23 Design (`docs/ROADMAP_DESIGN.md`)](ROADMAP_DESIGN.md)** — Validated specification for `WU-19a..WU-19d` and `WU-21..WU-28`

---

## 1. System & Target Split Overview

`peelf_viewer` (`apps/viewer/src/launcher.cpp`) is a lightweight Vulkan-free executable that links **only** `peelf_core` and `${CMAKE_DL_LIBS}`. When invoked with `--headless` or `--help`, it executes completely inside `peelf_core` without loading graphics libraries, making it suitable for minimal CI containers (`-DPEELF_BUILD_GUI=OFF` omits GUI compilation altogether). In interactive desktop sessions, `peelf_viewer` dynamically loads `peelf_gui` (`peelf_gui.dll` / `libpeelf_gui.so`) and invokes `peelf_run_gui()`.

```mermaid
flowchart LR
    user["Analyst / CI Job"]
    launcher["peelf_viewer<br/>Vulkan-free launcher"]
    cli["Headless CLI<br/>JSON + SARIF 2.1.0"]
    gui["peelf_gui<br/>Dynamic GUI module"]
    vk["VulkanManager<br/>2 frames-in-flight"]
    ui["UiApp + Panels<br/>Dear ImGui docking"]
    model["BinaryModel<br/>Static / Live / Dump / Debug"]
    core["peelf_core<br/>IBinaryImage + Runtime"]
    ext["External Tools<br/>Ghidra / llvm-mc / dot"]

    user --> launcher
    launcher -->|"--headless / --help"| cli
    cli --> core
    launcher -->|"dlopen / LoadLibraryExW"| gui
    gui --> vk
    gui --> ui
    ui --> model
    model --> core
    ui --> ext
    core --> ext
```

### Target Boundary Invariants
- **`peelf_core` (`libs/peelf_core`)**: Zero ImGui, GLFW, or Vulkan dependencies. Uses `peelf::Result<T> = std::expected<T, peelf::Error>` across API boundaries (`peelf/error.hpp`), forgiving `ForgivingValue<T>` / `SubsystemStatus` (`peelf/forgiving.hpp`), and first-class `TargetCapabilityMatrix` + `Observed<T>` provenance (`peelf/target_capabilities.hpp`, `WU-21`). Image parsing is modularized behind `<peelf/binary_image.hpp>` into `binary_image.cpp` (dispatch & container slice selection), `image_mapping.cpp` (`ImageBase` VA/RVA <-> file-offset mapping & live PE normalization), `pe_image.cpp` (`PeImage`), `elf_image.cpp` (`ElfImage` with explicit `parse_warnings()`), and `macho_image.cpp` (`MachOImage` + Universal `FAT_MAGIC`/`FAT_CIGAM_64`, `WU-26`). Also hosts `ExecutableSettings` (`WU-22`), `ProcessStateSnapshot` / `SnapshotDiff` (`WU-23`), `ExecutionTimeline` (`WU-24`), clean-room `GdbRemoteBackend` RSP (`WU-25`), and embedded MIT Lua 5.4.7 `LuaScriptingEngine` (`peelf/scripting.hpp`, `WU-28`).
- **`peelf_gui` (`apps/viewer`)**: Owns staged RAII `VulkanManager` (`UniqueTexture`) and `Application` (`std::unique_ptr<UiApp>`), `BinaryModel` (`binary_model.cpp` static/patching/scripting core + `binary_model_live.cpp` live/dump/debugger/GDB-RSP sessions), modular `UiApp` (`ui_app.cpp`, `ui_app_project.cpp`, `ui_app_menus_docking.cpp`, `ui_app_process.cpp`, `ui_app_graph.cpp`, `ui_app_navigation.cpp`), pure `DockNodeSpec` `WorkspaceLayout` v9 across 36 dockable panels & capability-aware `ContextActions` + `NavigationRequestQueue` (`WU-27`), `CallGraph` (`call_graph_dot.cpp`, `call_graph_build.cpp`, `call_graph_cfg.cpp`), background UI controllers (`AsyncReferenceScanner`, `AsyncBinaryDiffController`, `DecompileController`, `DecompileCache`, `BinaryModel::AsyncScriptRunner`), Capstone `Disassembler`, DIA/PDB symbol bridge, and `.peproj` v2 session management.
- **Compiler & Sanitizer Gate**: Project targets compile with `-Wall -Wextra -Wpedantic -Werror` on Clang/GCC and `/W4 /WX /FS` on MSVC (`PEELF_WARNINGS_AS_ERRORS=ON`), while `FetchContent` headers are isolated as `SYSTEM`. All `449/449` CTests pass under `clang18-debug`, `clang18-release`, and `clang18-asan-ubsan` (`AddressSanitizer` + `UndefinedBehaviorSanitizer`).

---

## 2. Unified `IBinaryImage` & Session Spine

The duplicate legacy `viewer::PeParser` / `PeModel` path was retired in `473ee3f` (`WU-18`). Every static view, live attached module view, offline crash dump module hydration, dependency resolver, binary differ, and security rule operates on `peelf::IBinaryImage` (`libs/peelf_core/include/peelf/binary_image.hpp`).

```mermaid
flowchart TD
    bytes["FileMapping / Byte Span"]
    parse["parse_image() / parse_mapped_image()"]
    pe["PeImage : IBinaryImage<br/>PE32/PE32+ + 16 Data Dirs"]
    elf["ElfImage : IBinaryImage<br/>ELF32/64 LE/BE + PT_DYNAMIC"]
    macho["MachOImage : IBinaryImage<br/>MH_MAGIC_64 + FAT_MAGIC_64"]
    paged["PagedBinaryImage<br/>Sparse patch transactions"]
    ro["IProcessSession (Read-Only)<br/>Win32 / Linux / GDB RSP"]
    dump["ICrashDumpSession : IProcessSession<br/>Win32 .dmp + ELF ET_CORE"]
    dbg["IDebugSession (Opt-in)<br/>ptrace / Win32 / GDB RSP"]
    hybrid["load_live_module_image()<br/>Live RAM + Rebased Disk Metadata"]
    model["BinaryModel + TargetCapabilityMatrix"]

    bytes --> parse
    parse --> pe
    parse --> elf
    parse --> macho
    bytes --> paged
    paged --> model
    pe --> model
    elf --> model
    macho --> model
    ro --> hybrid
    dump --> hybrid
    dbg --> hybrid
    hybrid --> model
```

### Format & Session Capabilities
- **PE32 / PE32+ (`PeImage`)**: Typed `PeFileHeaderInfo`, `PeOptionalHeaderInfo`, and `PeDataDirectoryEntry` accessors; standard, ordinal, bound, and delay-load imports; named, ordinal, and forwarded exports; base relocations; `.pdata`/`.xdata` unwind metadata; CodeView RSDS + MSF 7.00 Stream 1/3 GUID+Age verification; TLS callbacks; `WIN_CERTIFICATE` table; LoadConfig (SafeSEH, GuardCF, security cookie); resource directory trees (`RT_MANIFEST`, `RT_VERSION`); and CLR `BSJB` metadata (`WU-22`).
- **ELF32 / ELF64 LE/BE (`ElfImage`)**: Supports x86, x86-64, ARM32, ARM64, RISC-V 32/64, MIPS 32/64, and PowerPC 32/64; extended header numbering (`e_shnum == 0`, `SHN_XINDEX`, `PN_XNUM`); static sectionless `PT_DYNAMIC` symbol/relocation/import recovery (`DT_HASH` / `DT_GNU_HASH` / `DT_SYMTAB` / `DT_STRTAB` via `PT_LOAD` VA translation); notes (`.note.ABI-tag`, `.note.gnu.build-id`, `.note.gnu.property`); and DWARF v2–v5 + `.gnu_debuglink` sidecar hydration.
- **Cross-Endian Mach-O & Universal Containers (`MachOImage`, `WU-26`)**: Supports thin `MH_MAGIC`/`MH_MAGIC_64`/`MH_CIGAM`/`MH_CIGAM_64` and Universal `FAT_MAGIC`/`FAT_CIGAM`/`FAT_MAGIC_64`/`FAT_CIGAM_64` binaries (`parse_binary_container` + `BinaryModel::select_container_slice` + `--headless --slice <index|arch>`). Exposes container-absolute file offsets across fat slices, load commands, classic `nlist` & `LC_DYLD_EXPORTS_TRIE` / `LC_DYLD_CHAINED_FIXUPS`, structural `LC_CODE_SIGNATURE` SuperBlob/CodeDirectory/entitlements/CMS inspection, `@executable_path`/`@loader_path`/`@rpath` + `LC_REEXPORT_DYLIB` & honest dyld shared-cache `Dependencies`, and slice-matching `BinaryDiff`.
- **`TargetCapabilityMatrix` & First-Class Provenance (`WU-21`)**: Every loaded or attached target publishes explicit `SupportState` values (`SupportedValidated`, `SupportedExperimental`, `Partial`, `Unsupported` — defaulting strictly to `Unsupported` without evidence), `ProvenanceTag`, `CaptureAvailability`, `CaptureStamp` (`TargetInstanceId` + `snapshot_revision`), `BackingImageIdentity` verification, and `Observed<T>` wrappers surfaced in the `Target Capabilities` panel, `Executable & Settings` (`WU-22`), context-menu gating (`WU-27`), and `--headless` JSON.
- **Strictly Read-Only Live Inspection, Snapshots/Timelines & Opt-In Debugging (`WU-23..WU-25`)**:
  - Default `IProcessSession` (`Ctrl+P` local or `GdbRemoteBackend::open_read_only` over loopback-gated RSP) guarantees `is_read_only() == true` and never injects traps or writes memory.
  - `ProcessStateSnapshot` (`WU-23`) captures point-in-time telemetry (redacting sensitive environment secrets by default) and computes `TargetInstanceId`-verified `SnapshotDiff`s across modules, split/merged/RWX regions, threads, FDs (detecting FD reuse), and sockets. `ExecutionTimeline` (`WU-24`) merges `IDebugSession` events and `SnapshotDiff` deltas into per-thread UI swimlanes with explicit `SamplingGap` and `DroppedEvents` markers.
  - Offline crash dumps (`Minidump` `"MDMP"` and ELF `ET_CORE` with multi-arch `NT_PRSTATUS` decoding) implement `ICrashDumpSession : IProcessSession`, reusing every live inspection panel without executing target code.
  - Active debugging (`peelf::debugger::IDebugSession`) requires explicit opt-in (`ExplicitDebugConsent`), backed by BSD-2-Clause Linux `ptrace`, Win32 Debug API, and `GdbRemoteBackend::open_debug` (`vCont`/`Hc`, `Z0`–`Z4` software/hardware breakpoints & watchpoints, XXE-free `target.xml`/`memory-map`/`libraries-svr4` parsing, `xx`-preserving partial registers, shadowed memory reads, and truthful `detach()`).

---

## 3. Background Analysis, Decompilation & Session Persistence

Expensive static and cross-binary analyses run off the UI render thread with explicit progress, cancellation, or caching so 60+ FPS interactivity is preserved.

```mermaid
flowchart LR
    model["BinaryModel<br/>SHA-256 + edit_revision"]
    refscan["AsyncReferenceScanner<br/>std::jthread 256 KiB slices"]
    refidx["ReferenceIndex<br/>Direct + JumpTable + IAT/GOT"]
    stridx["StringsIndex<br/>ASCII / UTF-8 / UTF-16 xrefs"]
    diffctl["AsyncBinaryDiffController<br/>Revision-gated stop_token"]
    dcache["DecompileCache<br/>SHA-256 + patch/sym rev key"]
    ghidra["Persistent Ghidra LRU<br/>Off-/mnt/c ws-* projects"]
    peproj[".peproj v2 + Recovery<br/>Atomic .tmp + off-/mnt/c journal"]

    model --> refscan
    refscan --> refidx
    refidx --> stridx
    model --> diffctl
    model --> dcache
    dcache -->|"cache miss"| ghidra
    model --> peproj
    refidx --> peproj
```

- **Resumable `ReferenceIndex` (`WU-03`)**: `AsyncReferenceScanner` scans executable sections/regions in 256 KiB slices on a `std::jthread`, populating sorted `incoming`/`outgoing` xref vectors ($O(\log N + K)$ queries). Recovers direct branches/calls, guarded x86 absolute jump tables, x86/x64 PIC/RIP-relative `i32` tables, ARM Thumb-2 `tbb`/`tbh`, ARM64 PC-relative jump tables, and IAT/GOT indirect slots with `ReferenceConfidence` and `evidence` strings.
- **Two-Tier Persistent Decompilation (`WU-02`, `WU-19b`)**: `DecompileController` runs background decompilation on a `std::jthread` with latest-request replacement, per-job `std::stop_source` cancellation, and `(target_identity, file_generation, edit_revision, snapshot_revision)` validation stamps. `DecompileCache` caches `DecompiledUnit` results in memory by `(binary_sha256, patch_revision, symbol_revision, provider, settings_fingerprint, arch, endian, thumb, function_va)`. On cache miss, `GhidraDecompiler` reuses an LRU-bounded headless workspace (`ws-*` under `$PEELF_CACHE_DIR/ghidra_workspaces` or safe OS temp dir, never `/mnt/c` on WSL): cold imports run `analyzeHeadless -import` without `-deleteProject`, while subsequent functions run `-process -noanalysis` with incremental symbol sync and automatic cold-retry on stale project locks. In-tree `StructuredPseudoCDecompiler` provides an instant zero-dependency fallback.
- **Cancellable Binary Diff (`WU-12`, `WU-17`)**: `AsyncBinaryDiffController` executes `peelf::compare_binaries` (header, section, import, export, byte-hunk, and 3-tier `ExactName` / `NormalizedFingerprint` / `Similarity` function matching) on a background `std::jthread` with monotonic request IDs and `std::stop_token` cooperative cancellation. `peelf::compare_module_disk_to_live` normalizes relocations, LoadConfig cookies, and resolved IAT/GOT entries to isolate `.text` `InlineCodeHook` detours from `IatGotPointerHook` hijacks.
- **`.peproj` v2 Sessions & Crash Recovery (`WU-09`)**: Stores `source_sha256`, `source_size`, canonical `source`, and portable `relative_source` alongside staged patches, annotations, debug symbols, bookmarks, pinned `AppliedStructureBinding`s, history, and layout. Writes atomically via `.tmp` rename and maintains periodic off-`/mnt/c` recovery journals.

---

## 4. Panel Selection Hub, `DockNodeSpec` Workspaces & Universal Context Actions (`WU-27`)

Panels communicate through `ViewerSelection` (`apps/viewer/src/navigation/viewer_navigation.hpp`) and deferred `NavigationRequestQueue` (`apps/viewer/src/ui/context_actions.hpp`) rather than mutating peer panels or Dear ImGui tables mid-iteration.

- **Pure `DockNodeSpec` Workspace Engine (`workspace_layout.*`)**: Defines 5 deterministic `WorkspacePreset`s (*Static Reverse Engineering*, *Live Process / VMMap*, *Debugger*, *Binary Diff*, *Minimal*) over all 36 `WorkspacePanelId` windows (`kWorkspaceLayoutSchemaVersion = 9`), validated independent of ImGui/Vulkan for split-ratio bounds, non-duplicate leaf assignments, and active-tab determinism.
- **Capability-Aware Universal Context Menus (`context_actions.*`)**: `evaluate_context_actions` inspects `InspectableEntity` + `TargetCapabilityMatrix` to enable/disable `Copy VA / File Offset / Label / JSON Summary`, `Follow in Hex / Disassembly / Decompiler / Structure View`, `Add Bookmark`, and `Toggle Software Breakpoint` with explicit unavailable reasons, queuing navigation mutations for safe post-frame execution.

```mermaid
flowchart TD
    nav["Navigation Sources<br/>Structure / Sections / Symbols / Strings"]
    xref["Analysis Sources<br/>Flow Graph / Decompile / References / Scripting"]
    live["Runtime Sources<br/>Memory Map / Dependencies / Diff / Timeline / Debugger"]
    sel["ViewerSelection + NavigationRequestQueue<br/>kind, label, offset, VA, size, preferred_view"]
    details["Details Panel"]
    hex["Hex View<br/>Effective bytes + ?? unmapped"]
    disasm["Disassembly Panel<br/>Demangled labels + patch tint"]
    structv["Structure View<br/>Synced schema overlay"]

    nav --> sel
    xref --> sel
    live --> sel
    sel --> details
    sel --> hex
    sel --> disasm
    sel --> structv
```

---

## 5. Assembly Providers, Transactional Patching (`.pepatch.json`) & Sandboxed Lua 5.4 Scripting (`WU-28`)

```mermaid
flowchart TD
    ui["Hex View / Shellcode / Patch Set / Scripting"]
    lua["LuaScriptingEngine (MIT Lua 5.4.7)<br/>ScriptLimits + No io/os/debug/package"]
    req["AssembleRequest<br/>arch, mode, endian, base_va, asm"]
    reg["AssemblerRegistry"]
    asmtk["AsmTkAssemblerProvider<br/>In-process x86 / x86_64"]
    llvm["LlvmMcAssemblerProvider<br/>Safe argv llvm-mc multi-arch"]
    prev["PatchPreview + BundlePreview<br/>Round-trip disasm + slack + SHA-256 check"]
    tx["PagedBinaryImage::begin_transaction()<br/>Undo/Redo + Save Patched As (static only)"]

    ui --> req
    ui --> lua
    lua --> req
    lua -->|"peelf.commit() + UI-thread harvest"| tx
    req --> reg
    reg --> asmtk
    reg --> llvm
    asmtk --> prev
    llvm --> prev
    prev --> tx
```

`IAssemblerProvider` (`peelf/assembler.hpp`) dispatches little-endian x86/x86_64 assembly to `AsmTkAssemblerProvider` in-process and routes ARM, Thumb, AArch64, RISC-V 32/64, PowerPC 32/64, and MIPS 32/64 to `LlvmMcAssemblerProvider` via shell-free `argv` execution (`fork`/`execv` on POSIX, `CreateProcessW` on Windows). `.pepatch.json` bundles (`peelf/patch_bundle.hpp`) validate `expected_sha256`, `expected_size`, and per-entry `original_bytes_hex` before staging all spans inside one atomic `PatchTransaction`, rejecting live process sessions unconditionally.

`LuaScriptingEngine` (`peelf/scripting.hpp`) embeds MIT Lua 5.4.7 compiled strictly as C (`LUA_USE_LONGJMP`), isolating every `lua_*` boundary behind zero-destructor C++ trampolines + `lua_pcall`. A custom `lua_Alloc` enforces `ScriptLimits::max_memory_bytes`, a `LUA_MASKCOUNT` hook enforces `max_instructions`, `wall_clock_timeout`, and `std::stop_token` cancellation, `luaL_loadbufferx(..., "t")` rejects binary bytecode, and `io`/`os`/`debug`/`package`/`dofile`/`loadfile` are never opened. Scripts stage byte writes and annotations (`set_label`, `set_comment`, `add_bookmark`) against an isolated read-your-writes clone; mutations apply only when `allow_mutations == true` (static targets only) and `peelf.commit()` succeeds. In the GUI, `BinaryModel::AsyncScriptRunner` executes scripts on a cancellable `std::jthread` (`LaunchRollbackGuard` + non-allocating `catch`) and commits results on the UI thread via `harvest_script_execution()`, discarding stale outcomes if `(file_generation, slice_index, edit_revision, annotation_revision)` changed concurrently.

---

## 6. Vulkan 2-Frames-in-Flight Rendering Loop (`WU-18`)

`VulkanManager` (`apps/viewer/src/vulkan/vulkan_manager.*`) decouples CPU ImGui frame preparation from GPU presentation using `kMaxFramesInFlight = 2`:

```mermaid
flowchart LR
    glfw["GLFW Window Events<br/>Resize + Minimize Guard"]
    fence["Wait Frame Fence<br/>frame_index in 0..1"]
    acq["vkAcquireNextImageKHR<br/>image_available_sem[frame]"]
    cmd["Reset Pool + Record ImGui<br/>command_buffer[frame]"]
    sub["vkQueueSubmit<br/>render_finished_sem[image_idx]"]
    pres["vkQueuePresentKHR<br/>Swapchain Recreate on OutOfDate"]

    glfw --> fence
    fence --> acq
    acq --> cmd
    cmd --> sub
    sub --> pres
    pres -->|"next frame (frame + 1) % 2"| fence
```

- Each in-flight frame (`0` and `1`) owns an isolated `VkCommandPool`, `VkCommandBuffer`, `image_available` `VkSemaphore`, and `in_flight` `VkFence`.
- `render_finished` semaphores are indexed by acquired **swapchain `image_index`** rather than `frame_index` so semaphore reuse stays hazard-free under Vulkan validation layers across triple-buffered swapchains.
- Minimized zero-extent windows (`width == 0 || height == 0`) pause acquisition cleanly, and `VK_ERROR_OUT_OF_DATE_KHR` / `VK_SUBOPTIMAL_KHR` trigger `recreate_swapchain()` + `ImGui_ImplVulkan_SetMinImageCount()`.

---

## 7. Security Rule Engine, CI & Verification Matrix

```mermaid
flowchart LR
    matrix["bin-matrix/ + Malformed Matrix<br/>PE + ELF + Mach-O/FAT + Dumps"]
    presets["CMake Presets<br/>Clang 18 + ASan/UBSan + MSVC 2022"]
    gates["Compile Gates<br/>-Werror + /W4 /WX /FS + clang-tidy-18"]
    ctest["CTest Suite<br/>449 / 449 Unit & Integration Tests"]
    headless["peelf_viewer --headless<br/>JSON + SARIF 2.1.0 + --script"]
    gha[".github/workflows/ci.yml<br/>Ubuntu 24.04 + Windows 2022"]

    matrix --> ctest
    presets --> gates
    gates --> ctest
    gates --> headless
    ctest --> gha
    headless --> gha
```

- **Security Rules (`peelf/security_audit.hpp`)**: Evaluates `PE1001..PE1008`, `ELF2001..ELF2008`, `LIVE3001..LIVE3003`, and `MACHO4001..MACHO4006` with `Pass` / `Note` / `Warning` / `Error` severities, header/segment/region evidence, VA/offset locations, and compiler/linker remediation flags. `PE1005` (`SignBinaryWithAuthenticode`) and `MACHO4004` (`CodeSignatureAndHardenedRuntime`) strictly separate structural signature presence (`Note` when cryptographic OS trust verification is unavailable) from cryptographic trust verification.
- **Hostile-Input & Sanitizer Verification (`WU-16`, `WU-17`, `WU-25..WU-28`)**: `tests/malformed_inputs_matrix_test.cpp`, `tests/macho_test.cpp`, `tests/gdb_rsp_test.cpp`, and `tests/scripting_test.cpp` test wrap-around offsets, cyclic PE forwarders and ELF `sh_link` chains, `SHN_XINDEX`/`PN_XNUM`, malformed fat/Mach-O load commands & trie loops, XXE/oversized RSP packets, Lua instruction/memory/timeout bombs, and `0xFFFFFFFF` `ET_CORE` note alignments under `clang18-asan-ubsan`.



