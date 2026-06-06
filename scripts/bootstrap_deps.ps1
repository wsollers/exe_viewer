# =============================================================================
# LEGACY / UNSUPPORTED - DO NOT RUN
#
# This script is from an earlier dependency-vendoring approach and is no longer
# used by the build. Dependencies are fetched automatically via CMake
# FetchContent (see third_party/dependencies.cmake). Running this will NOT set
# the project up correctly and fetches versions that disagree with the build.
# Kept for historical reference only. See scripts/README.md.
# =============================================================================

$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$TP = Join-Path $Root "third_party"
New-Item -ItemType Directory -Force -Path $TP | Out-Null

function Clone-Or-Update([string]$Url, [string]$Dir, [string]$Tag) {
    if (Test-Path (Join-Path $Dir ".git")) {
        Write-Host "[+] Updating $Dir"
        git -C $Dir fetch --tags --prune | Out-Null
    } else {
        Write-Host "[+] Cloning $Url -> $Dir"
        git clone --depth 1 --branch $Tag $Url $Dir | Out-Null
    }
    Write-Host "[+] Checking out $Tag in $Dir"
    git -C $Dir checkout $Tag | Out-Null
}

Clone-Or-Update "https://github.com/glfw/glfw.git" (Join-Path $TP "glfw") "3.4"
Clone-Or-Update "https://github.com/ocornut/imgui.git" (Join-Path $TP "imgui") "v1.91.2"
Clone-Or-Update "https://github.com/KhronosGroup/Vulkan-Headers.git" (Join-Path $TP "Vulkan-Headers") "v1.3.290"

Write-Host "[+] Done. Dependencies are in third_party/"
