# scripts/

> **These scripts are legacy and unsupported. Do not run them.**

The project fetches all third-party libraries automatically via CMake
`FetchContent` (see `../third_party/dependencies.cmake`). There is no vendoring or
bootstrap step — just configure with CMake (see the top-level `README.md`).

The files here predate that approach and disagree with the actual build:

- `bootstrap_deps.ps1` / `bootstrap_deps.sh` — cloned GLFW `3.4`, ImGui `v1.91.2`,
  and Vulkan-Headers `v1.3.290` into `third_party/`. The current build uses
  different versions (ImGui `docking`, plus NFD and Capstone, with Vulkan from the
  installed SDK) and never reads these.
- `getdeps.ps1` — a larger vendoring script that also *generated* a
  `third_party/dependencies.cmake` and `README.md` describing vendored Vulkan
  loader / validation layers. None of that matches the current FetchContent build,
  and it invokes a `vendor_dependencies.ps1` that does not exist.

They are retained only for historical reference and may be removed entirely.
