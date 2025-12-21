# PE / ELF Explorer (C++23)

A cross-platform executable & shared-library viewer:
- **Core parsing library**: `peelf_core` (ELF + PE parsers)
- **GUI app**: `peelf_viewer` (Vulkan + GLFW + Dear ImGui)

## Toolchains
- **Clang 18** (recommended, with Ninja)
- **Visual Studio 2022+** (MSVC)

## Dependencies (vendored in `third_party/`)
This repo expects the following to live in `third_party/`:

- `third_party/glfw` (GLFW source checkout)
- `third_party/imgui` (Dear ImGui source checkout)
- `third_party/Vulkan-Headers` (optional; otherwise use your system Vulkan SDK headers)

A helper script is provided:

- Windows (PowerShell): `scripts/bootstrap_deps.ps1`
- Linux/macOS (bash): `scripts/bootstrap_deps.sh`

## Build (CMake Presets)
### Clang 18 + Ninja
```bash
cmake --preset clang18-debug
cmake --build --preset clang18-debug
```

### MSVC 2022
```powershell
cmake --preset msvc-debug
cmake --build --preset msvc-debug
```

## Notes
- This is an **initial scaffold**. The core library currently parses only minimal header fields for ELF/PE.
- Vulkan integration uses the system Vulkan loader. Install the Vulkan SDK if needed.
