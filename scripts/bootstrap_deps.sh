#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TP="${ROOT_DIR}/third_party"

mkdir -p "${TP}"

clone_or_update () {
  local url="$1"
  local dir="$2"
  local tag="$3"

  if [[ -d "${dir}/.git" ]]; then
    echo "[+] Updating ${dir}"
    git -C "${dir}" fetch --tags --prune
  else
    echo "[+] Cloning ${url} -> ${dir}"
    git clone --depth 1 --branch "${tag}" "${url}" "${dir}"
  fi

  echo "[+] Checking out ${tag} in ${dir}"
  git -C "${dir}" checkout "${tag}"
}

clone_or_update https://github.com/glfw/glfw.git "${TP}/glfw" "3.4"
clone_or_update https://github.com/ocornut/imgui.git "${TP}/imgui" "v1.91.2"
clone_or_update https://github.com/KhronosGroup/Vulkan-Headers.git "${TP}/Vulkan-Headers" "v1.3.290"

echo "[+] Done. Dependencies are in third_party/"
