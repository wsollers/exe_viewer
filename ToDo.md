# PE / ELF Explorer — Development Plan & ToDo

A roadmap to take `peelf_explorer` from an initial scaffold to a full cross-format
binary viewer (PE/ELF, exe/dll/so) with header/section/import-export inspection,
raw-byte view, disassembly, and decompilation — while paying down existing tech debt
and raising overall code quality.

> Legend: `[ ]` not started · `[~]` in progress · `[x]` done
> Task IDs (`P1-3`, `TD-2`, …) are referenced across sections so work can be tracked and cross-linked.
>
> **Progress (Phase 1):** Phase 0 complete (P0-1 … P0-10). Phase 1 in progress — P1-1 / P1-2 done; P1-3 / P1-4 implemented in the **core** (`PeImage` / `ElfImage` identity behind `IBinaryImage`, via `parse_image`), with the app-side migration (BinaryModel/panels onto `IBinaryImage`, removing the legacy parsers) still pending. Unit suite: 16 tests.

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
- [~] **P1-3** **PE parser (core done):** `PeImage` (internal to `binary_image.cpp`) parses DOS → PE signature → COFF → optional header (PE32/PE32+) for identity: machine→`Architecture`, `IMAGE_FILE_DLL`→`ImageKind`, magic→64-bit, entry VA = ImageBase + AddressOfEntryPoint, all bounds-checked. Tested via a synthetic PE32+ in `tests/binary_image_test.cpp`. **Remaining:** data directories + section table (Phase 2), and **removing the two legacy parsers** (`peelf::parse_pe_bytes`, `viewer::PeParser`) once the app's `BinaryModel` is migrated onto `IBinaryImage` (P1-6) — deferred because that step is GUI-coupled and not build-verifiable from here. (TD-5)
- [~] **P1-4** **ELF parser (core done):** `ElfImage` parses the ELF identity for both ELF32/ELF64 and **little- and big-endian** — the endian-aware readers in `binary_image.cpp` restore the BE support the old `parse_elf_bytes` rejected: class→64-bit, data→endianness, `e_type`→`ImageKind`, `e_machine`→`Architecture`, `e_entry`→entry point, bounds-checked. Reachable via the public `parse_image()`. Tested against `hello.elf`. **Remaining:** program headers (segments) + section headers (Phase 2), and wiring into the app load path (P1-6). (TD-6)
- [ ] **P1-5** Bounds-safety pass: every header/table read goes through checked accessors; fuzz the parsers against truncated/garbage input (ties into existing `fuzzing-experiments` interest).
- [ ] **P1-6** `BinaryModel`/viewmodel rebuilt on top of `IBinaryImage`; supports PE today, ELF as it lands.

**Exit criteria:** load a PE exe, PE dll, ELF exe, and ELF .so and get correct headers + `ImageKind` + architecture for each.

## 7. Phase 2 — Sections, segments & raw bytes

- [ ] **P2-1** Section model populated for both formats (name, vaddr/RVA, file offset, sizes, flags decoded to human-readable). ELF additionally surfaces program-header **segments** and the section↔segment mapping.
- [ ] **P2-2** Sections panel: sortable table, flag chips (R/W/X, code/data), click-through to the raw-byte view at that section's offset.
- [ ] **P2-3** Raw-bytes/hex view: virtualized hex+ASCII for large files (use the existing `FileMapping` so we don't load everything into RAM), offset/RVA toggle, go-to-offset, selection, and "follow" links from other panels.

**Exit criteria:** select a section in any loaded binary and land on its bytes in the hex view.

## 8. Phase 3 — Imports / exports / symbols

- [ ] **P3-1** **PE imports:** parse the import directory (and delay-load directory — note the existing `image_delay_load_descriptor.hpp`); resolve DLL names + named/ordinal functions; show the IAT.
- [ ] **P3-2** **PE exports:** parse the export directory (names, ordinals, forwarders).
- [ ] **P3-3** **ELF dynamic info:** `DT_NEEDED` libraries, dynamic symbol table (`.dynsym`), and (optionally) `.symtab`; relocations enough to label PLT/GOT entries.
- [ ] **P3-4** Map all of the above onto shared `ImportEntry`/`ExportEntry`/`Symbol` types so the panels are format-agnostic, with a small "format-specific extras" expander.

**Exit criteria:** imports/exports populate for a PE dll and "needed libs + dynamic symbols" populate for an ELF .so.

## 9. Phase 4 — Disassembly

The Capstone wrapper (`disassembler.hpp`) is solid; wire it into the model and UI.

- [ ] **P4-1** Pick disassembly target from `IBinaryImage` (architecture + the executable section's bytes + correct base/RVA).
- [ ] **P4-2** Disassembly panel: address / bytes / mnemonic / operands columns, syntax coloring (reuse the existing `is_branch/is_data_movement/is_simd/...` classifiers), and synchronized scrolling with the hex view.
- [ ] **P4-3** Navigation: jump from an import/export/section to its disassembly; resolve call/branch targets to symbol names where known.
- [ ] **P4-4** Verify Capstone ARM64 mode selection and add ARM/Thumb toggle hookup (TD-14).

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

**Exit criteria:** resize/minimize without crashes; consistent multi-panel layout; errors visible to the user.

## 12. Phase 7 — Quality, testing & CI

- [x] **P7-1** GoogleTest wired in via FetchContent under `tests/` (option `PEELF_BUILD_TESTS`, discovered by CTest) with a hello-world smoke test and an ELF-magic fixture test against `tests/fixtures/hello.elf`. _Next:_ dedicated PE/ELF parser tests using small fixture binaries + truncated/corrupt inputs (every new parser feature adds tests here).
- [ ] **P7-2** Golden-file tests comparing parsed summaries against known-good output for a handful of real exe/dll/so/elf samples.
- [ ] **P7-3** CI (GitHub Actions): build matrix {MSVC, Clang18+Ninja} × {Debug, Release}, run tests, run `clang-format --dry-run` and `clang-tidy`. Warnings-as-errors for our targets (C3).
- [ ] **P7-4 (TD-12)** Warning cleanup pass: resolve `-Wconversion`/`-Wsign-conversion` hits; replace C-style casts (e.g. in `vulkan_manager.cpp`) with named casts.
- [ ] **P7-5** Address-/UB-sanitizer build target for the parsers; run the fuzzers from `fuzzing-experiments` against them in CI (nightly).
- [ ] **P7-6** Docs: keep `README.md` build section current; add a short `ARCHITECTURE.md` describing `IBinaryImage` and the panel/viewmodel split.

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
