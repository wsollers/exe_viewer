# PE / ELF Explorer (C++23)

A cross-platform executable & shared-library viewer:
- **Core parsing library**: `peelf_core` (ELF + PE parsers, binary identity, sections/segments, imports/exports, symbols, relocations, PE data directories, and parser fixtures)
- **GUI app**: `peelf_viewer` (Vulkan + GLFW + Dear ImGui), with structure navigation, Details/Hex/Disassembly panels, PE-specific tables, symbol/import/export browsing, call graph rendering, and a shellcode scratch panel
- **Analysis integrations**: Capstone-backed disassembly, Graphviz-backed call graph layout, PDB/DIA symbol loading on Windows, and early AsmJit/AsmTK dependency support for future assembly-to-bytes providers

> Status: active development. The static PE/ELF parser and UI navigation paths are useful today, with richer PE/ELF spec coverage, live-process analysis, patch editing, and assembler/decompiler providers tracked in `ToDo.md`.

For architecture diagrams and data-flow notes, see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Toolchains

### UI resources and headless startup

The executable is a small launcher. It loads the optional `peelf_gui` module only
for interactive use. `peelf_viewer --headless` exits successfully without loading
graphics dependencies. A missing GUI module or unavailable graphics initialization
also exits successfully; failures after interactive startup still report failure.
Configure with `-DPEELF_BUILD_GUI=OFF` to build the launcher without Vulkan, GLFW,
ImGui, or native file dialogs. Headless analysis commands are not implemented yet.

The GUI loads `resources/theme.ini` beside the executable at startup. It contains
RGBA color tokens and spacing/rounding metrics. Use **View > Reload theme** to
apply edits, or **View > Interface scale** to adjust text size. Invalid resource
entries are ignored, with built-in defaults for missing values. Build outputs
include the resource directory; distribute it alongside the GUI module and launcher.

Theme parsing, fonts, menus, and rendering belong exclusively to the UI layer.
Binary models, parsers, navigation, symbols, disassembly, and patch operations
have no ImGui/GLFW/Vulkan dependency and are exercised by the non-GUI test binary.

Menus provide File, Edit, Navigate, Analyze, View, and Help commands. Ctrl+O opens
a binary; Ctrl+Shift+S exports a patched copy. Code views retain monospace fonts;
Windows interface controls use Segoe UI when available.

- **Visual Studio 2022** (MSVC v143, **17.6 or newer** — required for `std::expected`, `std::format`, and `std::byteswap`)
- **Clang 18** with **Ninja** (recommended on Linux)

## Prerequisites

You need all of the following before configuring:

- **CMake 3.25+**
- **Git** and a working network connection — third-party libraries are downloaded at configure time (see below)
- A **C++23** compiler (see Toolchains)
- The **Vulkan SDK** (from LunarG). The build calls `find_package(Vulkan REQUIRED)`, so the SDK must be installed and discoverable. The SDK installer sets the `VULKAN_SDK` environment variable for you.
- **Graphviz** is optional today, but recommended for call-flow / CFG rendering. The project emits DOT without it; installing Graphviz puts `dot` on `PATH` so CMake can define `PEELF_GRAPHVIZ_DOT_AVAILABLE=1` and the viewer can later render DOT through an external process.
- **Linux only:** GLFW's system dependencies, e.g. on Debian/Ubuntu:
  `sudo apt install xorg-dev libwayland-dev libxkbcommon-dev pkg-config graphviz`

### Graphviz on Windows

Install one of these, then open a new terminal so `PATH` is refreshed:

```powershell
# winget
winget install --id Graphviz.Graphviz -e

# or Chocolatey
choco install graphviz
```

Verify:

```powershell
dot -V
Get-Command dot
cmake --preset msvc-debug
```

If `dot` is not found, add Graphviz's `bin` directory to `PATH` manually. The
default installer path is usually `C:\Program Files\Graphviz\bin`.

## Dependencies (fetched automatically)

This project does **not** require any manual dependency vendoring. The file
`third_party/dependencies.cmake` uses CMake `FetchContent` to download and build
the following the first time you configure:

| Library | Version |
| --- | --- |
| GLFW | 3.4 |
| Dear ImGui | `docking` branch |
| nativefiledialog-extended | 1.2.1 |
| Capstone | 5.0.6 |
| AsmJit + AsmTK | pinned commits, optional assembly provider dependency |
| Graphviz | 13.0.0, optional source fetch |

Graphviz is optional and is not fetched unless `PEELF_ENABLE_GRAPHVIZ=ON`.
The Vulkan loader/headers are **not** fetched; they come from the installed Vulkan SDK.

> The scripts under `scripts/` (`bootstrap_deps.*`, `getdeps.ps1`) are legacy helpers from
> an earlier vendoring approach and are **not** used by the current build. You can ignore them.

## Build (CMake Presets)

Use the presets whenever possible. They keep build directories under `out/build/`
and match the paths used by the tests and fixture tooling.

### Windows: Visual Studio 2022 (MSVC)

Open a normal PowerShell prompt where Visual Studio and the Vulkan SDK are
discoverable. Graphviz is optional but recommended for call graph rendering.

```powershell
cmake --preset msvc-debug
cmake --build --preset msvc-debug
ctest --test-dir out/build/msvc-debug -C Debug --output-on-failure
```

Output binary: `out/build/msvc-debug/apps/viewer/Debug/peelf_viewer.exe`

To run the viewer directly:

```powershell
.\out\build\msvc-debug\apps\viewer\Debug\peelf_viewer.exe
```

### Linux: Clang 18 + Ninja

```bash
# Debug
cmake --preset clang18-debug
cmake --build --preset clang18-debug
ctest --test-dir out/build/clang18-debug --output-on-failure

# Release
cmake --preset clang18-release
cmake --build --preset clang18-release
```

Output binary: `out/build/<preset>/apps/viewer/peelf_viewer`

### Configure with options

Presets can be combined with `-D` cache options when configuring:

```bash
cmake --preset clang18-debug -DPEELF_ENABLE_GRAPHVIZ=ON -DPEELF_ENABLE_ASMTK=ON
cmake --build --preset clang18-debug
```

For Visual Studio multi-config builds, pass the configuration at build/test time:

```powershell
cmake --build --preset msvc-debug --config Debug
ctest --test-dir out/build/msvc-debug -C Debug --output-on-failure
```

### Clang Docker image

The repository includes a Clang 18 build image with Graphviz and cross compilers
for fixture generation:

```bash
docker build -f docker/Dockerfile.clang -t exe-viewer-clang .
docker run --rm -it -v "$PWD":/workspace/exe_viewer -w /workspace/exe_viewer exe-viewer-clang

cmake --preset clang18-debug
cmake --build --preset clang18-debug
ctest --test-dir out/build/clang18-debug --output-on-failure
```

The first configure will take a while because it clones and builds GLFW, ImGui,
nativefiledialog-extended, Capstone, and, by default, AsmJit/AsmTK. Enabling
`PEELF_ENABLE_GRAPHVIZ` also fetches the pinned Graphviz source tree for future
DOT rendering hooks.

### Cross-architecture fixture matrix

The checked-in `bin-matrix/` directory contains non-executable ELF/debug fixture
pairs used by parser, symbol, disassembly, and call-graph tests. Normal builds
use those committed files directly.

To refresh the matrix with Docker:

```powershell
cmake --build out/build/msvc-debug --target generate-bin-matrix
cmake --build out/build/msvc-debug --target test-bin-matrix
```

The generated filenames follow:

```text
elf-linux-<arch>-<bits>-<endian>-callgraph.elf
elf-linux-<arch>-<bits>-<endian>-callgraph.debug
```

To register the Docker-backed refresh as a CTest test, configure with
`-DPEELF_ENABLE_BIN_MATRIX_DOCKER_TEST=ON`. It is off by default because it
requires Docker and rewrites `bin-matrix/`.

## Build options

These CMake options are defined in the top-level `CMakeLists.txt`:

| Option | Default | Effect |
| --- | --- | --- |
| `PEELF_BUILD_VIEWER` | `ON` | Build the GUI viewer app (`peelf_viewer`) |
| `PEELF_BUILD_SHARED` | `ON` | Build `peelf_core` as a shared library |
| `PEELF_BUILD_TESTS` | `ON` | Build the GoogleTest unit suite |
| `PEELF_ENABLE_ASMTK` | `ON` | Fetch and build pinned AsmJit + AsmTK sources for optional assembly-to-bytes providers |
| `PEELF_ENABLE_GRAPHVIZ` | `OFF` | Fetch optional Graphviz source and expose Graphviz feature macros through `peelf::graphviz` |
| `PEELF_ENABLE_CLANG_TIDY` | `OFF` | Run clang-tidy on project targets for supported generators |
| `PEELF_ENABLE_BIN_MATRIX_DOCKER_TEST` | `OFF` | Register an opt-in CTest test that refreshes `bin-matrix/` with Docker and runs the focused matrix test |

## Running

Launch `peelf_viewer`, then **File → Open** and pick an executable
(`.exe`, `.dll`, `.so`, `.elf`). Use **File → Open Debug Symbols...** to load a
matching PDB when available. Use **View** to show or reset panels, including
Flow Graph, Disassembly, Symbols, Imports/Exports, PE tables, Log, and
Shellcode. Press `Esc` to quit.

The analysis workspace opens a control-flow preview at the entry point. Select a
function to view instruction-bearing basic blocks and directed branch edges.
Use the mouse wheel to zoom, middle-drag to pan, **Fit** for an overview, and
**100%** for readable code. Clicking a block synchronizes the byte selection and
disassembly. **Calls** switches to function relationships. Graph layout requires
Graphviz. Function bounds use symbol sizes or x64 PE runtime metadata, then the
next known function or executable region, capped at 16 KiB. The graph reports
which boundary source was used. Unknown indirect branches remain explicitly
unresolved. Guarded absolute x86 jump tables are recovered only when all entries
are available and point to decoded instructions; other table forms remain
unresolved. Applied byte edits refresh the active graph.

Double-click a graph instruction or listing address to follow a direct target.
Use **Back/Forward**, `Backspace` / `Shift+Backspace`, or `Alt+Left` / `Alt+Right`
to retrace navigation, `Space` to
switch between graph and listing, arrow keys to select code, and `Enter` to
follow a selected direct target. These shortcuts do not interfere with text
entry. Graph instructions and the listing show resolved symbol names.

Open **References** from the toolbar or press `X` for **References & Notes**.
Filter incoming/outgoing references for the selection, or search addresses,
symbols, referenced ASCII strings, user names, and comments. Source and target
addresses navigate independently. Reference analysis scans up to 4 MiB of
executable section bytes, reports partial coverage, and refreshes on patch or
Thumb-mode changes while the panel is open. This is a conservative static scan:
address constants are distinguished from memory references, and
register-dependent targets are not guessed.

Names and comments are currently session-only and cleared on loading a binary.
They appear in the function list, graph, and listing; original symbols remain
searchable. Project persistence is a separate planned feature.

## Notes

- Dear ImGui is pinned to a known `docking` commit in `third_party/dependencies.cmake`.
- Vulkan integration uses the system Vulkan loader from the SDK.
