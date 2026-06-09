# PE / ELF Explorer (C++23)

A cross-platform executable & shared-library viewer:
- **Core parsing library**: `peelf_core` (ELF + PE parsers, plus a cross-platform memory-mapping wrapper)
- **GUI app**: `peelf_viewer` (Vulkan + GLFW + Dear ImGui), with section listing, PE header inspection, a hex view, and Capstone-based disassembly

> Status: initial scaffold. The core library currently parses only minimal ELF/PE header fields, and the GUI's live load path handles PE (`MZ`) files. ELF wiring in the GUI is not complete yet.

## Toolchains

- **Visual Studio 2022** (MSVC v143, **17.6 or newer** — required for `std::expected`, `std::format`, and `std::byteswap`)
- **Clang 18** with **Ninja** (recommended on Linux)

## Prerequisites

You need all of the following before configuring:

- **CMake 3.25+**
- **Git** and a working network connection — third-party libraries are downloaded at configure time (see below)
- A **C++23** compiler (see Toolchains)
- The **Vulkan SDK** (from LunarG). The build calls `find_package(Vulkan REQUIRED)`, so the SDK must be installed and discoverable. The SDK installer sets the `VULKAN_SDK` environment variable for you.
- **Linux only:** GLFW's system dependencies, e.g. on Debian/Ubuntu:
  `sudo apt install xorg-dev libwayland-dev libxkbcommon-dev pkg-config`

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
| Graphviz | 13.0.0, optional source fetch |

Graphviz is optional and is not fetched unless `PEELF_ENABLE_GRAPHVIZ=ON`.
The Vulkan loader/headers are **not** fetched; they come from the installed Vulkan SDK.

> The scripts under `scripts/` (`bootstrap_deps.*`, `getdeps.ps1`) are legacy helpers from
> an earlier vendoring approach and are **not** used by the current build. You can ignore them.

## Build (CMake Presets)

### Visual Studio 2022 (MSVC)

```powershell
cmake --preset msvc-debug
cmake --build --preset msvc-debug
```

Output binary: `out/build/msvc-debug/apps/viewer/Debug/peelf_viewer.exe`

### Clang 18 + Ninja

```bash
# Debug
cmake --preset clang18-debug
cmake --build --preset clang18-debug

# Release
cmake --preset clang18-release
cmake --build --preset clang18-release
```

Output binary: `out/build/<preset>/apps/viewer/peelf_viewer`

The first configure will take a while because it clones and builds GLFW, ImGui,
nativefiledialog-extended, and Capstone. Enabling `PEELF_ENABLE_GRAPHVIZ` also
fetches the pinned Graphviz source tree for future DOT rendering hooks.

## Build options

These CMake options are defined in the top-level `CMakeLists.txt`:

| Option | Default | Effect |
| --- | --- | --- |
| `PEELF_BUILD_VIEWER` | `ON` | Build the GUI viewer app (`peelf_viewer`) |
| `PEELF_BUILD_SHARED` | `ON` | Build `peelf_core` as a shared library |
| `PEELF_BUILD_TESTS` | `ON` | Build the GoogleTest unit suite |
| `PEELF_ENABLE_GRAPHVIZ` | `OFF` | Fetch optional Graphviz source and expose Graphviz feature macros through `peelf::graphviz` |
| `PEELF_ENABLE_CLANG_TIDY` | `OFF` | Run clang-tidy on project targets for supported generators |

## Running

Launch `peelf_viewer`, then **File → Open** and pick an executable
(`.exe`, `.dll`, `.so`, `.elf`). Press `Esc` to quit.

## Notes

- Dear ImGui is currently pinned to its moving `docking` branch tip, and the Vulkan
  backend integration relies on recent backend API fields. If a fresh `FetchContent`
  pull breaks the viewer build, pin ImGui to a known-good commit in
  `third_party/dependencies.cmake`.
- Vulkan integration uses the system Vulkan loader from the SDK.
