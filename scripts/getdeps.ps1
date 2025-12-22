#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Vendors GLFW, ImGui, and Vulkan SDK components into the third_party directory.

.DESCRIPTION
    This script clones/downloads the latest stable releases of:
    - GLFW (windowing/input library)
    - Dear ImGui (immediate mode GUI)
    - Vulkan-Headers (Vulkan API headers)
    - Vulkan-Loader (Vulkan runtime loader)
    - Vulkan-ValidationLayers (optional, for debugging)

.PARAMETER ThirdPartyDir
    The directory to place vendored dependencies. Defaults to "./third_party".

.PARAMETER IncludeValidationLayers
    If specified, also vendors Vulkan-ValidationLayers (large, slow to build).

.PARAMETER Clean
    If specified, removes existing vendored directories before cloning.

.EXAMPLE
    ./vendor_dependencies.ps1
    ./vendor_dependencies.ps1 -ThirdPartyDir "deps" -IncludeValidationLayers
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ThirdPartyDir = "./third_party",

    [Parameter()]
    [switch]$IncludeValidationLayers,

    [Parameter()]
    [switch]$Clean
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Dependency definitions: Name, Repo URL, Tag/Branch (empty = latest release)
$Dependencies = @(
    @{
        Name        = "glfw"
        Repo        = "https://github.com/glfw/glfw.git"
        Tag         = ""  # Will fetch latest release
        Description = "Multi-platform windowing and input library"
    },
    @{
        Name        = "imgui"
        Repo        = "https://github.com/ocornut/imgui.git"
        Tag         = ""  # Will fetch latest release
        Description = "Dear ImGui - Immediate mode GUI"
    },
    @{
        Name        = "Vulkan-Headers"
        Repo        = "https://github.com/KhronosGroup/Vulkan-Headers.git"
        Tag         = ""  # Will fetch latest release
        Description = "Vulkan API headers"
    },
    @{
        Name        = "Vulkan-Loader"
        Repo        = "https://github.com/KhronosGroup/Vulkan-Loader.git"
        Tag         = ""  # Will fetch latest release
        Description = "Vulkan runtime loader"
    },
    @{
        Name        = "Vulkan-Utility-Libraries"
        Repo        = "https://github.com/KhronosGroup/Vulkan-Utility-Libraries.git"
        Tag         = ""
        Description = "Vulkan utility libraries (required by loader)"
    }
)

if ($IncludeValidationLayers) {
    $Dependencies += @{
        Name        = "Vulkan-ValidationLayers"
        Repo        = "https://github.com/KhronosGroup/Vulkan-ValidationLayers.git"
        Tag         = ""
        Description = "Vulkan validation layers for debugging"
    }
}

function Write-Status {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host ">>> " -ForegroundColor $Color -NoNewline
    Write-Host $Message
}

function Write-Error-Message {
    param([string]$Message)
    Write-Host "ERROR: " -ForegroundColor Red -NoNewline
    Write-Host $Message
}

function Test-GitInstalled {
    try {
        $null = git --version
        return $true
    }
    catch {
        return $false
    }
}

function Get-LatestReleaseTag {
    param([string]$Repo)

    try {
        # Use git ls-remote to find tags, filter for version-like tags
        $tags = git ls-remote --tags --refs $Repo 2>$null
        if (-not $tags) {
            return $null
        }

        # Parse tags and find the latest semantic version
        $versionTags = $tags | ForEach-Object {
            if ($_ -match "refs/tags/(.+)$") {
                $tag = $Matches[1]
                # Match common version patterns: v1.2.3, 1.2.3, sdk-1.2.3, etc.
                if ($tag -match "^v?(\d+\.\d+(\.\d+)?(\.\d+)?)$" -or
                        $tag -match "^sdk-(\d+\.\d+\.\d+)") {
                    return $tag
                }
            }
        } | Where-Object { $_ }

        if ($versionTags) {
            # Sort by version number (simplified - takes last which is usually highest)
            $sorted = $versionTags | Sort-Object {
                $v = $_ -replace "^v|^sdk-", ""
                [version]($v -replace "\.(\d+)\.(\d+)\.(\d+)$", '.$1')
            }
            return $sorted[-1]
        }
    }
    catch {
        Write-Verbose "Failed to get latest release tag: $_"
    }

    return $null
}

function Install-Dependency {
    param(
        [hashtable]$Dep,
        [string]$TargetDir
    )

    $name = $Dep.Name
    $repo = $Dep.Repo
    $tag = $Dep.Tag
    $destPath = Join-Path $TargetDir $name

    Write-Status "Processing: $name" "Yellow"
    Write-Host "    $($Dep.Description)"

    # Clean existing if requested
    if ($Clean -and (Test-Path $destPath)) {
        Write-Host "    Removing existing directory..."
        Remove-Item -Path $destPath -Recurse -Force
    }

    # Skip if already exists
    if (Test-Path $destPath) {
        Write-Host "    Already exists, skipping (use -Clean to re-download)"
        return $true
    }

    # Determine tag to use
    if (-not $tag) {
        Write-Host "    Fetching latest release tag..."
        $tag = Get-LatestReleaseTag -Repo $repo
        if ($tag) {
            Write-Host "    Found latest release: $tag"
        }
        else {
            Write-Host "    No release tags found, using default branch"
        }
    }

    # Clone the repository
    Write-Host "    Cloning repository..."

    $cloneArgs = @("clone", "--depth", "1")
    if ($tag) {
        $cloneArgs += @("--branch", $tag)
    }
    $cloneArgs += @($repo, $destPath)

    try {
        $output = & git @cloneArgs 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "Git clone failed: $output"
        }
        Write-Host "    Successfully cloned $name" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error-Message "Failed to clone $name : $_"
        return $false
    }
}

function New-CMakeIntegrationFile {
    param([string]$TargetDir)

    $cmakeContent = @'
# Auto-generated CMake integration for vendored dependencies
# Include this file in your CMakeLists.txt: include(third_party/dependencies.cmake)

# GLFW
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/glfw/CMakeLists.txt")
    set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
    set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(GLFW_INSTALL OFF CACHE BOOL "" FORCE)
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/glfw")
    message(STATUS "Found vendored GLFW")
endif()

# Dear ImGui (requires manual setup - it's not a CMake project)
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/imgui/imgui.h")
    set(IMGUI_DIR "${CMAKE_CURRENT_LIST_DIR}/imgui")

    add_library(imgui STATIC
        "${IMGUI_DIR}/imgui.cpp"
        "${IMGUI_DIR}/imgui_demo.cpp"
        "${IMGUI_DIR}/imgui_draw.cpp"
        "${IMGUI_DIR}/imgui_tables.cpp"
        "${IMGUI_DIR}/imgui_widgets.cpp"
    )
    target_include_directories(imgui PUBLIC "${IMGUI_DIR}")

    # ImGui backends (add as needed)
    if(TARGET glfw)
        target_sources(imgui PRIVATE "${IMGUI_DIR}/backends/imgui_impl_glfw.cpp")
        target_include_directories(imgui PUBLIC "${IMGUI_DIR}/backends")
        target_link_libraries(imgui PUBLIC glfw)
    endif()

    # Vulkan backend
    if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/Vulkan-Headers/include/vulkan/vulkan.h")
        target_sources(imgui PRIVATE "${IMGUI_DIR}/backends/imgui_impl_vulkan.cpp")
        target_include_directories(imgui PUBLIC
            "${IMGUI_DIR}/backends"
            "${CMAKE_CURRENT_LIST_DIR}/Vulkan-Headers/include"
        )
    endif()

    message(STATUS "Found vendored Dear ImGui")
endif()

# Vulkan-Headers
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/Vulkan-Headers/CMakeLists.txt")
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/Vulkan-Headers")
    message(STATUS "Found vendored Vulkan-Headers")
endif()

# Vulkan-Utility-Libraries (required by Vulkan-Loader)
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/Vulkan-Utility-Libraries/CMakeLists.txt")
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/Vulkan-Utility-Libraries")
    message(STATUS "Found vendored Vulkan-Utility-Libraries")
endif()

# Vulkan-Loader
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/Vulkan-Loader/CMakeLists.txt")
    # The loader needs to find headers
    set(VULKAN_HEADERS_INSTALL_DIR "${CMAKE_CURRENT_LIST_DIR}/Vulkan-Headers" CACHE PATH "" FORCE)
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/Vulkan-Loader")
    message(STATUS "Found vendored Vulkan-Loader")
endif()

# Vulkan-ValidationLayers (optional)
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/Vulkan-ValidationLayers/CMakeLists.txt")
    add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/Vulkan-ValidationLayers")
    message(STATUS "Found vendored Vulkan-ValidationLayers")
endif()
'@

    $cmakePath = Join-Path $TargetDir "dependencies.cmake"
    Set-Content -Path $cmakePath -Value $cmakeContent -Encoding UTF8
    Write-Status "Created CMake integration file: $cmakePath" "Green"
}

function New-ReadmeFile {
    param([string]$TargetDir)

    $readmeContent = @"
# Third-Party Dependencies

This directory contains vendored third-party dependencies.

## Contents

- **glfw/** - Multi-platform windowing and input library
- **imgui/** - Dear ImGui immediate mode GUI library
- **Vulkan-Headers/** - Vulkan API headers from Khronos
- **Vulkan-Loader/** - Vulkan runtime loader
- **Vulkan-Utility-Libraries/** - Vulkan utility libraries

## Usage

Include the generated CMake file in your project:

```cmake
cmake_minimum_required(VERSION 3.16)
project(MyApp)

include(third_party/dependencies.cmake)

add_executable(myapp main.cpp)
target_link_libraries(myapp PRIVATE
    glfw
    imgui
    Vulkan::Vulkan  # or Vulkan::Headers for headers-only
)
```

## Updating

Re-run the vendor script with the ``-Clean`` flag to update all dependencies:

```powershell
./vendor_dependencies.ps1 -Clean
```

## Generated

This directory was generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
"@

    $readmePath = Join-Path $TargetDir "README.md"
    Set-Content -Path $readmePath -Value $readmeContent -Encoding UTF8
    Write-Status "Created README: $readmePath" "Green"
}

# Main execution
function Main {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Dependency Vendoring Script" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Check for git
    if (-not (Test-GitInstalled)) {
        Write-Error-Message "Git is not installed or not in PATH"
        exit 1
    }

    # Resolve and create target directory
    $TargetDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ThirdPartyDir)

    if (-not (Test-Path $TargetDir)) {
        Write-Status "Creating directory: $TargetDir"
        New-Item -Path $TargetDir -ItemType Directory -Force | Out-Null
    }

    Write-Status "Target directory: $TargetDir"
    Write-Host ""

    # Process each dependency
    $success = 0
    $failed = 0

    foreach ($dep in $Dependencies) {
        if (Install-Dependency -Dep $dep -TargetDir $TargetDir) {
            $success++
        }
        else {
            $failed++
        }
        Write-Host ""
    }

    # Generate helper files
    Write-Host ""
    New-CMakeIntegrationFile -TargetDir $TargetDir
    New-ReadmeFile -TargetDir $TargetDir

    # Summary
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Successful: $success" -ForegroundColor Green
    if ($failed -gt 0) {
        Write-Host "  Failed:     $failed" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "Include in your CMakeLists.txt:" -ForegroundColor Yellow
    Write-Host "  include(third_party/dependencies.cmake)" -ForegroundColor White
    Write-Host ""

    if ($failed -gt 0) {
        exit 1
    }
}

Main