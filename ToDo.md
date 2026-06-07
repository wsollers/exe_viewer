# PE / ELF Explorer — Development Plan & ToDo

A roadmap to take `peelf_explorer` from an initial scaffold to a full cross-format
binary viewer (PE/ELF, exe/dll/so) with header/section/import-export inspection,
raw-byte view, disassembly, and decompilation — while paying down existing tech debt
and raising overall code quality.

> Legend: `[ ]` not started · `[~]` in progress · `[x]` done
> Task IDs (`P1-3`, `TD-2`, …) are referenced across sections so work can be tracked and cross-linked.
>
> **Progress (Phase 1):** Phase 0 complete (P0-1 … P0-10). Phase 1 in progress — P1-1 / P1-2 done; P1-3 / P1-4 implemented in the **core** (`PeImage` / `ElfImage` identity behind `IBinaryImage`, via `parse_image`), with the app-side migration (BinaryModel/panels onto `IBinaryImage`, removing the legacy parsers) still pending. Unit suite: 23 tests. The app load path now calls `parse_image()` (ELF files load; PE panels still on the legacy `PeModel`); full panel migration + legacy-parser removal pending. Phase 2 started: section tables parsed for PE/ELF (P2-1), ELF program-header segments parsed and shown in the Sections panel, and `IBinaryImage` now exposes checked file-offset ↔ virtual-address mapping. Phase 3 started: ELF `.symtab` / `.dynsym` symbols parse into shared `Symbol` values and display in a Symbols panel; ELF `DT_NEEDED` libraries and PE import directories parse into shared `ImportEntry` values and display in a unified Imports panel; PE export directories parse into shared `ExportEntry` values and display in a unified Exports panel. Deterministic parser fixtures now cover PE32/PE32+, ELF32/ELF64, and little-/big-endian ELF identity plus `.text` mapping. Disassembler is now initialized from the unified image (PE **and** supported ELF architectures), ELF entry-point disassembly resolves through core VA→file-offset mapping, clicking a byte in the Hex view disassembles a window using the mapped VA when available (P4-1 partial), unsupported architectures no longer fall back to bogus x64 disassembly, and ARM64 Capstone mode setup is covered by tests; also fixed an ELF crash in `on_file_loaded` (unconditional null-`pe()` deref, exposed once ELF files began loading).

---

## 1. Goals

1. **One model, many formats.** Parse PE and ELF uniformly behind a common interface, exposing shared concepts (sections, symbols, imports/exports, entry point, architecture) plus format-specific detail. Correctly distinguish executables vs. shared libraries (exe/dll vs. so).
2. **Five core views**, each format-aware:
   - Headers / summary (PE COFF + optional header; ELF header + program headers)
   - Sections (and ELF segments)
   - Imports / Exports (PE import/export tables; ELF dynamic symbols + needed libraries)
   - Raw bytes (hex/ASCII, with navigation to file offsets / RVAs)
   - Disassembly (Capstone) and **Decompilation** (pseudo-C)
3. **Production-quality code.** Consistent style, real error handling, no dead/duplicate paths, tests, and CI.

> **Testing is mandatory and gating.** Every feature — current and new — must have unit tests.
> A change (feature, refactor, or tech-debt fix) is **not complete** until the full unit-test
> suite builds and passes (`ctest` green). GoogleTest is the framework; tests live in `tests/`.
> No exceptions: code without passing tests is treated as unfinished.

## 2. Key decisions & open questions

Resolve these before the phases they gate; defaults are the recommended path.

- **D1 — Decompiler backend (gates Phase 5b).** Options:
  - *RetDec* (LLVM-based, open source) invoked as a subprocess, output parsed and displayed. **Recommended default** — good quality, no Java, swappable.
  - *Ghidra headless* (`analyzeHeadless` + export script) — best quality, but heavyweight Java dependency.
  - *In-tree pseudocode-lite only* — function/basic-block reconstruction over Capstone; lowest fidelity, no extra deps.
  - **Decision:** wrap whatever we pick behind `IDecompiler` (Phase 5a) so the choice is reversible. _Owner to confirm D1 default._
- **D2 — GUI scope.** Stay with Dear ImGui + Vulkan (current stack) vs. simplify the renderer. **Default: keep ImGui**, but harden the Vulkan layer (TD-7, TD-13) and pin ImGui (TD-10).
- **D3 — Platform priority.** **Default: Windows (MSVC) is primary** (matches current dev box), Linux/Clang kept green in CI.
- **D4 — Min toolchains.** C++23 requires VS 2022 ≥ 17.6 / Clang 18 + libstdc++ 13. Confirm we can require these.

## 3. Target architecture

Proposed layout (incremental migration, not a big-bang rewrite):

```
libs/peelf_core/
  include/peelf/
    error.hpp          # Error + Result<T> = std::expected<T, Error>
    byte_reader.hpp    # fixed endian-aware reader (no broken vtable)
    binary_image.hpp   # IBinaryImage interface + shared value types
    pe/                # PeImage : IBinaryImage
    elf/               # ElfImage : IBinaryImage
    mapping/           # FileMapping (cleaned up)
  src/ …
apps/viewer/
  src/
    app/               # application, main, config
    render/            # vulkan_manager + imgui glue   (was vulkan/)
    panels/            # UI panels                      (was ui/)
    disasm/            # disassembler (spelling fixed)  (was dissassembler/)
    decompile/         # IDecompiler + backend adapter
    viewmodel/         # adapts core IBinaryImage -> panel-friendly data
```

**Shared value types** (in `binary_image.hpp`): `Architecture`, `Endianness`,
`ImageKind { Executable, SharedLibrary, Object, Core, Unknown }`, `Section`,
`Segment`, `Symbol`, `ImportEntry`, `ExportEntry`, `RelocationGroup`, `StringRef`.
`IBinaryImage` exposes these uniformly; PE/ELF-only extras are reachable via the
concrete type (downcast) or a `format_details()` `std::variant`.

## 4. Cross-cutting conventions

- [ ] **C1** — Error handling: `Result<T> = std::expected<T, peelf::Error>` everywhere in core; no silent failure, no exceptions across the core API boundary (exceptions allowed only at the app's `main`/Vulkan layer).
- [ ] **C2** — Naming/style: snake_case for funcs/locals, `PascalCase` types, trailing `_` for members; enforce via `.clang-format` (already present) + `.clang-tidy` (new).
- [ ] **C3** — Warnings are errors in CI for our own targets (keep third-party warnings suppressed). Current flags already include `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion` / `/W4 /permissive-`.
- [ ] **C4** — **Testing is mandatory and gating.** Every feature, fix, and refactor — current and new — ships with unit tests, and the complete `ctest` suite must build and pass before the change is considered complete. GoogleTest is the framework, wired in under `tests/` (gated by `PEELF_BUILD_TESTS`, discovered by CTest). Backfill tests for existing functionality as it is touched.
- [~] **C5** — Fixed-width primitive cleanup: binary-facing data and parser/disassembler paths should use `std::uint*_t` / `std::size_t` rather than implementation-sized aliases. First pass covered the unified parser, disassembler wrapper, key UI disassembly paths, smoke-test byte handling, and PE address-map overflow helpers. Remaining: legacy PE parser structs/helpers, Vulkan/GLFW-required callback integers, and text-facing `char` buffers that must stay compatible with C APIs.

---

## 5. Phase 0 — Tech-debt cleanup & foundations — COMPLETE

**Status: complete (P0-1 … P0-10)** — clean build + green test suite on MSVC. Each item maps to the
**Tech Debt Register** in §13.

- [x] **P0-1 (TD-1)** Doc/dependency reconciliation finished. Rewrote `third_party/README.md` to describe the FetchContent reality (GLFW 3.4, ImGui `docking`, NFD v1.2.1, Capstone 5.0.6; Vulkan from the installed SDK; no vendored dirs). Added a `LEGACY / UNSUPPORTED - DO NOT RUN` banner to `scripts/bootstrap_deps.ps1`, `scripts/bootstrap_deps.sh`, and `scripts/getdeps.ps1`, and added `scripts/README.md` documenting why they're legacy. (`README.md` was already updated earlier.) Docs-only — no build/test impact.
- [x] **P0-2 (TD-10)** Pinned Dear ImGui in `third_party/dependencies.cmake` to docking commit `2af6dd9694288e6befe1edb7ce25510911693c22` (2026-06-04) instead of the moving `docking` tip. Verified via GitHub that this commit's `backends/imgui_impl_vulkan.h` contains every `ImGui_ImplVulkan_InitInfo` field `application.cpp` sets (`PipelineInfoMain`/`PipelineInfoForViewports`, `ApiVersion`, `DescriptorPoolSize`, `MinAllocationSize`, `CustomShaderVert/FragCreateInfo`). Set `GIT_SHALLOW FALSE` (shallow clone can't check out an arbitrary SHA) and updated `third_party/README.md`. _Note:_ the top-level `FETCHCONTENT_UPDATES_DISCONNECTED ON` means a clean reconfigure (or clearing the imgui `_deps` entries) is needed for the new pin to take effect.
- [x] **P0-3 (TD-3)** Fixed `mapping/file_mapping.hpp`: removed the self-`#include`; **moved the OS-backend `#include`s to global scope** (they were nested inside `namespace peelf`, which defined the backends as `peelf::peelf::*` and left `NativeFileMappingBackend` bound to an incomplete type — only masked previously by the redundant top-level include); corrected the `// namespace ws::fs` comments to `peelf` across all mapping headers/sources; and removed the unused `win32_ec`/`posix_ec` static helpers (cleared MSVC C4505).
- [x] **P0-4 (TD-2)** `FileMapping`: the throwing constructor now reports failure via `std::system_error` (no more discarded `error_code`), with `open()` retained as the non-throwing/`error_code` path. **Also fixed a latent move bug** found while writing tests: move-assignment transferred `backend_`/`byte_size_` but not `data_`, so a moved-to mapping reported `is_open()==false` and ownership was split incorrectly. Covered by `tests/file_mapping_test.cpp` (4 tests: read-only map, ctor-throws, open()-error, move ownership).
- [x] **P0-5 (TD-11)** Renamed `apps/viewer/src/dissassembler/dissassembler.hpp` → `apps/viewer/src/disasm/disassembler.hpp` (via the connector's `move_file`) and fixed the four `#include`s (`application.h`, `application.cpp`, `ui/ui_app.hpp`, `ui/ui_panels.hpp`) plus the `apps/viewer/CMakeLists.txt` source entry. Type names (`Disassembler`, `Instruction`, `Architecture`) were already spelled correctly. Pure rename, no behavior change — gated by the green suite + viewer build. The now-empty `src/dissassembler/` folder can be removed with `rmdir` (git won't track it once committed). Disassembler unit tests come with Phase 4 (P4-x) when it's wired into the model and linked against capstone.
- [x] **P0-6 (TD-5)** Removed the dead `gui/gui.cpp` + `gui/gui.h` path (duplicate `open_file_dialog`/`load_file` free functions and the unused `menubar` struct) from the `peelf_viewer` build, and dropped the stale `#include "gui/gui.h"` from `application.cpp`. The live flow is unchanged (`Application::open_file_dialog` → `BinaryModel::load_file`; menu via `UiApp::render_main_menu`). Also clears the C4189 unused-local warnings. _Manual step (no delete tool available to the assistant):_ `git rm apps/viewer/src/gui/gui.cpp apps/viewer/src/gui/gui.h`. (Consolidating the two PE parsers — `peelf::parse_pe_bytes` vs `viewer::PeParser` — is tracked under P1-3.)
- [x] **P0-7 (TD-9)** `Application::open_file_dialog` now frees the NFD path with `NFD_FreePath` (was `free`), and `NFD_Init`/`NFD_Quit` are paired once at startup/shutdown (guarded by a `nfd_initialized_` flag so `NFD_Quit` only runs after a successful init) instead of `NFD_Init` on every open. Added `NFD_ERROR` handling via the logger. _No isolated unit test:_ this is native-dialog resource management with no pure-logic seam; gated by the green suite + a manual check that Open works and shutdown is clean. A testable `IFileDialog` seam can be added later if desired.
- [x] **P0-8 (TD-4)** Removed the unused, broken `IByteReader`/`byte_reader`/`make_reader` trio from `peelf/peelf.hpp` (non-virtual "interface" with undefined base methods — `make_reader` could never dispatch; also relied on `<bit>`/`<cstring>`/`<memory>` transitively). Left a note pointing to P1-4 where a proper endian reader returns with the unified model. Added `tests/peelf_core_test.cpp` covering `peelf::to_string(FileKind)` — the core's first direct unit test.
- [x] **P0-9** Added `libs/peelf_core/include/peelf/error.hpp` with `Error`, `Result<T> = std::expected<T, Error>`, and a `make_error("...")` helper that captures the call-site `source_location` (the robust defaulted-parameter idiom). Moved `Error` out of `peelf.hpp` (which now includes `error.hpp`); **declared** `parse_pe_bytes`/`parse_elf_bytes` publicly returning `Result<FileInfo>` (they were defined-but-undeclared); migrated both `.cpp` parsers from `std::unexpected(Error{...})` to `make_error(...)`. Added `tests/parsers_test.cpp` (4 tests): ELF success path against `hello.elf` (class/data/type/machine asserts) plus ELF and PE error paths. Suite now 12 tests. (Public declaration also unblocks the P1-3 parser consolidation.)
- [x] **P0-10** Added `.clang-tidy` (baseline: bugprone / performance / portability / modernize / misc / clang-analyzer / readability with the noisy checks disabled, `HeaderFilterRegex` scoped to `libs/peelf_core`, `apps/viewer/src`, `tests`; not yet gating). Wired into CMake: opt-in `PEELF_ENABLE_CLANG_TIDY` sets `CXX_CLANG_TIDY` **per target** (peelf_core / peelf_viewer / peelf_tests only — never the FetchContent deps; Ninja/clang presets only, since the VS generator ignores it), plus `format` / `format-check` custom targets driven by the existing `.clang-format`. CI enforcement is P7-3; the warning backlog is P7-4. Default builds are unchanged (option OFF; format targets are inert unless invoked).

**Exit criteria:** clean configure+build on MSVC and Clang with no warnings from our targets; no dead code paths; docs match build.

## 6. Phase 1 — Unified core parsing model

- [x] **P1-1** Added `libs/peelf_core/include/peelf/binary_image.hpp`: the `IBinaryImage` interface plus shared value types `Format`, `ImageKind`, `Architecture`, `Endianness`, and `Section`, each with a `to_string`. Concrete images are internal to `binary_image.cpp`; callers use `parse_image()`. (Symbols/imports/exports join the interface in Phase 3; `Section` is populated in Phase 2.)
- [x] **P1-2** `detect_format()` dispatches on `\x7fELF` / `MZ` (unknown magic rejected gracefully by `parse_image`). `ImageKind` is populated from the PE `IMAGE_FILE_DLL` characteristic and the ELF `e_type` (`ET_EXEC`→Executable, `ET_DYN`→SharedLibrary, `ET_REL`→Object, `ET_CORE`→Core). _Caveat:_ PIE executables are `ET_DYN` and currently report as SharedLibrary; `DT_FLAGS_1`/`DF_1_PIE` disambiguation is deferred to Phase 3 (dynamic info).
- [~] **P1-3** **PE parser (core done):** `PeImage` (internal to `binary_image.cpp`) parses DOS → PE signature → COFF → optional header (PE32/PE32+) for identity: machine→`Architecture`, `IMAGE_FILE_DLL`→`ImageKind`, magic→64-bit, entry VA = ImageBase + AddressOfEntryPoint, all bounds-checked. Tested via synthetic PE32+ plus deterministic PE32 and PE32+ fixtures. **Remaining:** data directories + section table (Phase 2), and **removing the two legacy parsers** (`peelf::parse_pe_bytes`, `viewer::PeParser`) once the app's `BinaryModel` is migrated onto `IBinaryImage` (P1-6) — deferred because that step is GUI-coupled and not build-verifiable from here. (TD-5)
- [~] **P1-4** **ELF parser (core done):** `ElfImage` parses the ELF identity for both ELF32/ELF64 and **little- and big-endian** — the endian-aware readers in `binary_image.cpp` restore the BE support the old `parse_elf_bytes` rejected: class→64-bit, data→endianness, `e_type`→`ImageKind`, `e_machine`→`Architecture`, `e_entry`→entry point, bounds-checked. Reachable via the public `parse_image()` and now **wired into the app** (`BinaryModel::load_file`, see P1-6) so ELF files load. Tested against `hello.elf` plus deterministic ELF32 little-endian, ELF32 big-endian, ELF64 little-endian, and ELF64 big-endian fixtures. **Remaining:** program headers (segments) + section headers (Phase 2). (TD-6)
- [~] **P1-5** Bounds-safety pass: every header/table read goes through checked accessors; fuzz the parsers against truncated/garbage input (ties into existing `fuzzing-experiments` interest). **Progress:** unified PE/ELF parser section-table and optional-header arithmetic now uses subtractive/checked range logic; PE optional-header magic is validated; tests cover unsupported PE optional magic and an overflowing ELF section table. Remaining: convert all parser reads to a shared checked `ByteReader`/cursor and fuzz broadly.
- [~] **P1-6** First slice done (additive, low-risk): `BinaryModel::load_file` now calls `peelf::parse_image()` and stores a `std::unique_ptr<peelf::IBinaryImage>`, exposed via `BinaryModel::image()`. **ELF files now load in the app for the first time** — the File panel shows format/arch/kind/endianness/64-bit/entry from the unified image, and the Hex view works (bytes are read). PE still flows through the legacy `PeModel`/`PeParser`, so the PE-specific panels are untouched; every PE panel already guards on `pe()==null`, so ELF is safe (those panels just show "No PE file loaded"). **Remaining:** migrate the PE-specific panels onto `IBinaryImage`, then delete the legacy parsers (`viewer::PeParser` + core `parse_pe_bytes`/`parse_elf_bytes`); and factor the viewer model into a small library so `BinaryModel` is unit-testable (today it's app-only, gated by the core tests + the viewer build).

**Exit criteria:** load a PE exe, PE dll, ELF exe, and ELF .so and get correct headers + `ImageKind` + architecture for each.

## 7. Phase 2 — Sections, segments & raw bytes

- [~] **P2-1** Section **table** populated for both formats in `binary_image.cpp`, exposed via `IBinaryImage::sections()`: name (PE inline 8-char; ELF resolved via `.shstrtab`), virtual address (PE = ImageBase+RVA; ELF `sh_addr`), virtual size, file offset/size (ELF `SHT_NOBITS`→0), and R/W/X (PE `IMAGE_SCN_MEM_*`; ELF `SHF_ALLOC`/`WRITE`/`EXECINSTR`), all bounds-checked. ELF program-header **segments** are now parsed via `IBinaryImage::segments()` with type, file/virtual ranges, and R/W/X flags. Tested against `hello.elf`, deterministic ELF64 x86-64 / ARM64 / RISC-V64 fixtures, and a PE32+ x64 fixture. App: the Sections panel shows sections and ELF segments from `IBinaryImage`. **Remaining:** section↔segment mapping; click-through to hex — P2-2/P2-3.
- [~] **P2-2** Sections panel migrated onto `IBinaryImage`: reads `model_.image()->sections()` / `segments()` (one source for PE and ELF) and shows **R/W/X permission flags** instead of a raw hex value, uniformly across formats. `IBinaryImage` also now owns checked file-offset ↔ virtual-address mapping over parsed sections, covered by PE/ELF fixture tests. **Remaining:** sortable columns, code/data chips, and click-through to the hex view at the section's offset (needs cross-panel selection state — pairs with P2-3). _Note:_ `BinaryModel::sections()` (the legacy `SectionInfo` vector) is now read by no panel — a cleanup candidate once the remaining panels migrate.
- [ ] **P2-3** Raw-bytes/hex view: virtualized hex+ASCII for large files (use the existing `FileMapping` so we don't load everything into RAM), offset/RVA toggle, go-to-offset, selection, and "follow" links from other panels. _(Fixed a pre-existing duplicate-ImGui-ID bug here: each byte cell's `Selectable` now carries a unique `##<offset>` suffix in its label.)_

**Exit criteria:** select a section in any loaded binary and land on its bytes in the hex view.

## 8. Phase 3 — Imports / exports / symbols

- [~] **P3-1** **PE imports:** parse the import directory (and delay-load directory — note the existing `image_delay_load_descriptor.hpp`); resolve DLL names + named/ordinal functions; show the IAT. **Progress:** unified `PeImage` parses named PE imports into shared `ImportEntry` values with library, function name, and IAT VA; deterministic PE32+ x64 fixture covers `KERNEL32.dll!ExitProcess`. Remaining: ordinal imports, delay-load imports, malformed import-table negative tests.
- [~] **P3-2** **PE exports:** parse the export directory (names, ordinals, forwarders). **Progress:** unified `PeImage` parses named PE exports into shared `ExportEntry` values and the unified Exports panel displays them; deterministic PE32+ x64 fixture covers one named export. Remaining: forwarder fixture/test coverage and malformed export-table negative tests.
- [~] **P3-3** **ELF dynamic info:** `DT_NEEDED` libraries, dynamic symbol table (`.dynsym`), and (optionally) `.symtab`; relocations enough to label PLT/GOT entries. **Progress:** `.symtab` and `.dynsym` symbols are parsed into shared `Symbol` values (name, address, size, binding, type, section index, table kind), and `DT_NEEDED` libraries are parsed into shared `ImportEntry` values. Covered by deterministic ELF64 x86-64 / ARM64 / RISC-V64 fixtures. Remaining: relocations, PLT/GOT labels, and richer real-world fixture coverage.
- [~] **P3-4** Map all of the above onto shared `ImportEntry`/`ExportEntry`/`Symbol` types so the panels are format-agnostic, with a small "format-specific extras" expander. **Progress:** shared `Symbol` / `ImportEntry` / `ExportEntry` types, Symbols panel, unified Imports panel, and unified Exports panel exist. Remaining: format-specific extras and retiring legacy PE-specific panels after confidence builds.
- [ ] **P3-5** **ELF full-spec metadata backlog:** relocations (`.rel*` / `.rela*`), PLT/GOT mapping, additional dynamic tags beyond `DT_NEEDED`, symbol versioning (`.gnu.version*`), GNU hash / SysV hash tables, notes (`PT_NOTE`, `.note.*`), GNU properties, interpreter (`PT_INTERP`), TLS, init/fini arrays, compressed sections, section groups, and OS/processor-specific flags. Keep each feature behind shared value types where possible and add targeted malformed-table tests.
- [ ] **P3-6** **PE full-spec metadata backlog:** base relocations, resources, TLS directory, load config / CFG / security metadata, exception/unwind data (`.pdata` / `.xdata`), debug directory / CodeView records, certificate table, bound imports, CLR/COM descriptor, section COMDAT/COFF symbol data, rich header (optional), and overlay detection. Add PE DLL fixture coverage and malformed-table tests as each lands.
- [ ] **P3-7** **Debug symbol lookup:** support external symbol/debug information association and lookup. PE: PDB discovery from CodeView debug records, local PDB path handling, symbol server configuration, and optional DIA/LLVM/PDB backend. ELF: DWARF discovery from `.debug_*`, build-id lookup, split debug files, `.gnu_debuglink`, and local debug package paths. Results should feed shared symbol/name lookup for panels, disassembly labels, and future decompilation.

**Exit criteria:** imports/exports populate for a PE dll and "needed libs + dynamic symbols" populate for an ELF .so.

## 9. Phase 4 — Disassembly

The Capstone wrapper (`disassembler.hpp`) is solid; wire it into the model and UI.

- [~] **P4-1** Disassembler architecture is now selected from `IBinaryImage::architecture()` (mapped to the Capstone wrapper's enum) on load, for **both** PE and ELF. The Hex view's click-to-disassemble (`UiApp::disassemble_at_offset`) disassembles a 256-byte window of raw bytes at the clicked file offset and uses core file-offset → VA mapping when available. ELF entry-point disassembly now resolves entry VA → file offset through `IBinaryImage`; PE still uses the legacy `PeModel` path until the remaining PE panels migrate. **Remaining:** auto-pick the executable section's bytes in all cases and synchronize navigation with sections/imports/exports.
- [ ] **P4-2** Disassembly panel: address / bytes / mnemonic / operands columns, syntax coloring (reuse the existing `is_branch/is_data_movement/is_simd/...` classifiers), and synchronized scrolling with the hex view.
- [ ] **P4-3** Navigation: jump from an import/export/section to its disassembly; resolve call/branch targets to symbol names where known.
- [~] **P4-4** Verify Capstone ARM64 mode selection and add ARM/Thumb toggle hookup (TD-14). **Progress:** ARM64 initialization no longer uses the ARM32 mode flag; focused disassembler tests cover x86-64 and ARM64 NOP decoding; unsupported parser architectures such as ELF RISC-V64 do not fall back to x64 disassembly. Remaining: complete ARM/Thumb UI hookup.

**Exit criteria:** open a binary, jump to entry point, see correctly disassembled code with working branch navigation.

## 10. Phase 5 — Decompilation

- [ ] **P5a-1** Define `IDecompiler` abstraction (`decompile(function_or_range) -> Result<DecompiledUnit>`), independent of backend (D1).
- [ ] **P5a-2** In-tree **pseudocode-lite** first pass: function boundary detection, basic-block/CFG reconstruction over Capstone output, annotated/structured listing. Ships without external deps and validates the UI.
- [ ] **P5b-1** Integrate the chosen real backend (D1; default RetDec via subprocess): detect availability, run on the selected function/range, parse output into `DecompiledUnit`.
- [ ] **P5b-2** Decompile panel: C-like output with line→address mapping, synchronized highlight with the disassembly panel, graceful "backend not installed" state.

**Exit criteria:** select a function and see pseudo-C; with the backend installed, see real decompiled C synced to the disassembly.

## 11. Phase 6 — UI/UX & rendering hardening

- [ ] **P6-1 (TD-7)** Handle `VK_ERROR_OUT_OF_DATE_KHR` / `VK_SUBOPTIMAL_KHR` from `vkAcquireNextImageKHR` and `vkQueuePresentKHR` → trigger swapchain recreation instead of throwing/crashing on resize.
- [ ] **P6-2 (TD-13)** Move to proper frames-in-flight sync (per-frame semaphores/fences) rather than a single reused set.
- [ ] **P6-3 (TD-8)** Make font-texture upload explicit and version-correct in `init_imgui` rather than relying on a comment/lazy init.
- [ ] **P6-4** Docking layout with the five panels, persisted window state, recent-files list, and an About dialog (currently a TODO).
- [ ] **P6-5** File-open robustness: surface parse errors to the log panel (the `Logger` already exists) instead of failing silently.
- [ ] **P6-6 (TD-16)** Collapse the duplicate **Disassembly** window: both `DisassemblyPanel::draw()` and `UiApp::render_disassembly_panel()` call `ImGui::Begin("Disassembly")` each frame, so the same-named window is opened twice and content from both appends into one window. Pick a single renderer (the table view in `render_disassembly_panel()` is the richer one) and drop the other, or have the panel delegate to it. Also remove the dead `disasm_panel_.current_instructions_ = current_instructions_` self-assignment in `UiApp::render()` (it assigns a reference member to itself).
- [ ] **P6-7** **Live process viewing:** enumerate running processes, choose a target, and open a read-only live image view. Windows: process list, module list, memory-region map, `ReadProcessMemory`-backed byte provider, bitness/session/access checks, and graceful permission failures. Linux: `/proc` process/module/maps view and `process_vm_readv` or `/proc/<pid>/mem` where permitted. The UI should distinguish file-backed image parsing from live-memory views and surface stale/unreadable regions clearly.
- [ ] **P6-8** **Live image parsing model:** adapt `IBinaryImage` concepts to loaded modules where file offsets may not exist, sections are mapped at runtime addresses, relocations are applied, and pages can be missing/unreadable. Add process-module navigation, live memory hex view, and disassembly over mapped ranges. Keep this separate from static-file parsing so tests can use a fake memory provider.

**Exit criteria:** resize/minimize without crashes; consistent multi-panel layout; errors visible to the user.

## 12. Phase 7 — Quality, testing & CI

- [x] **P7-1** GoogleTest wired in via FetchContent under `tests/` (option `PEELF_BUILD_TESTS`, discovered by CTest) with a hello-world smoke test and an ELF-magic fixture test against `tests/fixtures/hello.elf`. _Next:_ dedicated PE/ELF parser tests using small fixture binaries + truncated/corrupt inputs (every new parser feature adds tests here).
- [~] **P7-2** Golden-file tests comparing parsed summaries against known-good output for a handful of real exe/dll/so/elf samples. **Progress:** added deterministic non-executable parser fixtures for ELF64 x86-64, ELF64 ARM64, ELF64 RISC-V64, ELF32 little-endian x86, ELF32 big-endian MIPS, ELF64 big-endian PowerPC64, PE32 x86, and PE32+ x86-64, plus tests for architecture, kind, endianness, entry point, `.text` permissions, and core address mapping. Remaining: real-world exe/dll/so samples and richer golden summaries.
- [ ] **P7-3** CI (GitHub Actions): build matrix {MSVC, Clang18+Ninja} × {Debug, Release}, run tests, run `clang-format --dry-run` and `clang-tidy`. Warnings-as-errors for our targets (C3).
- [ ] **P7-4 (TD-12)** Warning cleanup pass: resolve `-Wconversion`/`-Wsign-conversion` hits; replace C-style casts (e.g. in `vulkan_manager.cpp`) with named casts.
- [ ] **P7-5** Address-/UB-sanitizer build target for the parsers; run the fuzzers from `fuzzing-experiments` against them in CI (nightly).
- [ ] **P7-6** Docs: keep `README.md` build section current; add a short `ARCHITECTURE.md` describing `IBinaryImage` and the panel/viewmodel split.
- [ ] **P7-7 Parser robustness matrix** — grouped parser tests for malformed but plausible tables, not random bytes. Covers: PE import/export truncation and invalid RVAs; PE ordinal imports; PE forwarder exports; PE delay-load imports; ELF bad `sh_link`, bad `sh_entsize`, truncated `.dynamic`, invalid string offsets; ELF `.dynsym` distinct from `.symtab`; ELF relocations/PLT/GOT once implemented. These should be table-driven and fixture-backed where possible.
- [~] **P7-8 Cross-format fixture matrix** — known, documented, non-executable fixtures for PE exe, PE dll, ELF executable, and ELF `.so` across supported architectures. Minimum target: Win x64 exe+dll; Linux x64 exe+so; Linux ARM64 exe+so; Linux RISC-V64 exe+so. **Progress:** deterministic coverage exists for PE32/PE32+, ELF32/ELF64, and little-/big-endian ELF parser identity and `.text` mapping. Remaining: PE DLL fixtures, Linux `.so` fixtures, richer golden assertions for imports/exports/symbols on every supported arch, and real-world non-random samples where licensing permits.
- [ ] **P7-9 Disassembly behavior tests** — model-level tests for entry-point disassembly and mapped-address disassembly, not only Capstone wrapper tests. Covers: PE entry point, ELF entry point, x86-32 mode, ARM32 mode, ARM Thumb toggle, ARM64 fixture disassembly, unsupported-architecture behavior (RISC-V64 parses but disassembly is disabled), file-offset→VA mapping during hex-click disassembly, and range limiting so disassembly never reads beyond section/file bounds.
- [ ] **P7-10 Navigation behavior tests** — once navigation is implemented, test it in a viewer-model layer independent of ImGui/Vulkan. Covers: section→hex, segment→hex, import/export/symbol→hex or disassembly, offset/RVA/VA display-mode switching, go-to-offset, go-to-VA, selection state persistence, and failure cases for virtual-only bytes, invalid RVAs, and unmapped VAs. Highlighting tests stay deferred until the UI decision is made.
- [ ] **P7-11 Debug symbol tests** — deterministic fixtures for PDB/CodeView and DWARF lookup flows. Include local-path hit, missing-file miss, symbol-server-disabled behavior, split-debug/build-id lookup, and merged symbol-name resolution in disassembly labels.
- [ ] **P7-12 Live process tests** — isolate live-process logic behind fake process/memory providers so CI can test process/module enumeration, region permissions, partial reads, stale mappings, module unload behavior, and live-memory VA navigation without requiring privileged OS process access.

**Exit criteria:** green CI on both toolchains with tests, lint, and warnings-as-errors.

## 13. Tech Debt Register

Each item is owned by a Phase-0/6/7 task above.

| ID | Issue | Location | Fix task |
| --- | --- | --- | --- |
| TD-1 | Docs claim vendored deps + bootstrap scripts; build actually uses FetchContent | `README.md` (fixed), `third_party/README.md`, `scripts/*` | P0-1 |
| TD-2 | `FileMapping` ctor discards `open()`'s `error_code`; silent failure + unused-var warning | `mapping/file_mapping.hpp` | P0-4 |
| TD-3 | Header self-include + duplicate win32 include; wrong namespace comments | `mapping/file_mapping.hpp`, `file_mapping_win32.hpp` | P0-3 |
| TD-4 | `IByteReader` methods non-virtual → no polymorphic dispatch from `make_reader` | `peelf/peelf.hpp` | P0-8 |
| TD-5 | Two PE parsers + dead `gui.cpp` load path + unused `menubar` | `gui/gui.cpp`, core vs `model/pe_parser` | P0-6, P1-3 |
| TD-6 | ELF path unwired; `parse_elf_bytes` undeclared; `parse_file` commented out | `elf/elf_parser.cpp`, `peelf/peelf.hpp` | P1-4 |
| TD-7 | Swapchain out-of-date/suboptimal not handled; `check()` throws on resize | `vulkan/vulkan_manager.cpp` | P6-1 |
| TD-8 | ImGui fonts never explicitly uploaded (comment only) | `application.cpp` `init_imgui` | P6-3 |
| TD-9 | NFD path freed with `free()` instead of `NFD_FreePath` | `application.cpp` | P0-7 |
| TD-10 | ImGui pinned to moving `docking` branch tip → non-reproducible | `third_party/dependencies.cmake` | P0-2 |
| TD-11 | "dissassembler" misspelling (dir/file/usage) | `apps/viewer/src/dissassembler/` | P0-5 |
| TD-12 | `-Wconversion`/`-Wsign-conversion` hits; C-style casts | multiple, esp. `vulkan_manager.cpp` | P7-4 |
| TD-13 | Single-frame-in-flight; reused semaphores | `vulkan_manager.cpp` | P6-2 |
| TD-14 | Capstone ARM64 mode/option review | `disassembler.hpp` | P4-4 |
| TD-15 | No tests, CI, or lint enforcement | repo-wide | P7-1..P7-3 |
| TD-16 | Duplicate `Disassembly` ImGui window (`DisassemblyPanel::draw` + `render_disassembly_panel` both `Begin("Disassembly")`); plus a dead reference self-assign | `ui/ui_app.cpp`, `ui/ui_panels_disasm.cpp` | P6-6 |

## 14. Suggested sequencing

1. **Phase 0** (debt + foundations) — unblocks all.
2. **Phase 1** (unified model) — the spine everything hangs off.
3. **Phases 2 → 3 → 4** (sections/bytes → imports/exports → disasm) — incremental, each demo-able.
4. **Phase 6** rendering hardening can run in parallel once Phase 0 lands.
5. **Phase 5** (decompile) after Phase 4 and the D1 decision.
6. **Phase 7** (tests/CI) starts during Phase 1 (parsers are the highest-value test target) and continues throughout.

## 15. Backlog / stretch

- [ ] Mach-O support (third format) behind the same `IBinaryImage`.
- [ ] String extraction view; entropy/packer heuristics.
- [ ] Symbol demangling (Itanium + MSVC).
- [ ] PDB / DWARF debug-info association for better names in disasm/decompile.
- [ ] Search across sections (byte patterns, strings, regex).
- [ ] Export views to JSON/CSV.
- [ ] Diff two binaries.
