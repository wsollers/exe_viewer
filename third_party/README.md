# Third-Party Dependencies

This project does **not** vendor third-party source into this directory. All
third-party libraries are fetched and built automatically by CMake `FetchContent`
at configure time, driven by `dependencies.cmake` in this folder (which the
top-level `CMakeLists.txt` includes).

There are therefore **no** `glfw/`, `imgui/`, `Vulkan-Headers/`, etc.
subdirectories to populate, and no vendoring step to run.

## What gets fetched (`dependencies.cmake`)

| Library | Version / ref | Notes |
| --- | --- | --- |
| GLFW | `3.4` | Windowing/input. Docs, tests, examples, install disabled. |
| Dear ImGui | `docking` @ `2af6dd96` (pinned) | Built here as a static `imgui` target with the GLFW + Vulkan backends; links `glfw` and `Vulkan::Vulkan`. |
| nativefiledialog-extended (NFD) | `v1.2.1` | Native open/save file dialogs (`nfd` target). |
| Capstone | `5.0.6` | Disassembler. Static only; X86, ARM, and ARM64 enabled. |

> **Reproducibility note:** Dear ImGui is pinned to a specific `docking`-branch
> commit (`2af6dd96`, 2026-06-04), verified to contain the Vulkan-backend
> `ImGui_ImplVulkan_InitInfo` fields the viewer uses. To move it, pick a newer
> docking commit and re-verify those fields in `backends/imgui_impl_vulkan.h`
> (see the comment in `dependencies.cmake`).

## Not fetched: the Vulkan SDK

`dependencies.cmake` calls `find_package(Vulkan REQUIRED)`, so the Vulkan loader
and headers come from an installed **Vulkan SDK** (LunarG), not FetchContent. The
commented-out `Vulkan-Headers` block is intentionally disabled. Install the SDK
and ensure `VULKAN_SDK` is set (the installer does this).

## How it's used

The top-level `CMakeLists.txt` does:

```cmake
include(third_party/dependencies.cmake)
```

after which targets can link `glfw`, `imgui`, `nfd`, `capstone`, and
`Vulkan::Vulkan`. The **first** configure clones and builds these, so it takes
noticeably longer than subsequent configures.

## Legacy scripts

The helpers under `../scripts/` (`bootstrap_deps.ps1`, `bootstrap_deps.sh`,
`getdeps.ps1`) are from an earlier *vendoring* approach and are **no longer used
or supported** — they fetch different versions and would write a different
`dependencies.cmake` / `README.md` than the build actually uses. Do not run them.
See `../scripts/README.md`.
