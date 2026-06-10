#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
source_file="${script_dir}/cross_callgraph_fixture.c"
out_dir="${repo_root}/bin-matrix"

rm -rf "${out_dir}"
mkdir -p "${out_dir}"

cat > "${out_dir}/README.md" <<'README'
# Binary Fixture Matrix

Generated cross-architecture fixtures used by the parser, symbol, disassembly,
and call-graph tests.

Naming convention:

`elf-linux-<arch>-<bits>-<endian>-callgraph.elf`
`elf-linux-<arch>-<bits>-<endian>-callgraph.debug`

Where:

- `<arch>` is the parser architecture token (`x86`, `x86_64`, `arm`, `arm64`,
  `riscv64`, `mips`, `mips64`, `ppc`, `ppc64`).
- `<bits>` is `32` or `64`.
- `<endian>` is `le` or `be`.
- `.elf` is the stripped-debug executable image under test.
- `.debug` is the detached debug sidecar produced with `objcopy --only-keep-debug`.

The generated files intentionally have execute permission removed.
README

common_flags=(
  -std=c11
  -O0
  -g
  -fno-inline
  -fno-omit-frame-pointer
  -fno-optimize-sibling-calls
  -fno-pie
  -no-pie
  -Wl,--build-id=none
)

build_fixture() {
  local cc="$1"
  local objcopy="$2"
  local name="$3"
  shift 3

  local image="${out_dir}/${name}.elf"
  local debug="${out_dir}/${name}.debug"

  "${cc}" "${common_flags[@]}" "$@" "${source_file}" -o "${image}"
  "${objcopy}" --only-keep-debug "${image}" "${debug}"
  "${objcopy}" --strip-debug --add-gnu-debuglink="${debug}" "${image}"
  chmod a-x "${image}" "${debug}"
}

build_fixture gcc objcopy elf-linux-x86_64-64-le-callgraph
build_fixture i686-linux-gnu-gcc i686-linux-gnu-objcopy elf-linux-x86-32-le-callgraph
build_fixture arm-linux-gnueabihf-gcc arm-linux-gnueabihf-objcopy elf-linux-arm-32-le-callgraph -marm
build_fixture aarch64-linux-gnu-gcc aarch64-linux-gnu-objcopy elf-linux-arm64-64-le-callgraph
build_fixture riscv64-linux-gnu-gcc riscv64-linux-gnu-objcopy elf-linux-riscv64-64-le-callgraph \
  -march=rv64g \
  -mabi=lp64d \
  -mno-relax
build_fixture mips-linux-gnu-gcc mips-linux-gnu-objcopy elf-linux-mips-32-be-callgraph
build_fixture mips64-linux-gnuabi64-gcc mips64-linux-gnuabi64-objcopy elf-linux-mips64-64-be-callgraph
build_fixture powerpc-linux-gnu-gcc powerpc-linux-gnu-objcopy elf-linux-ppc-32-be-callgraph
build_fixture powerpc64-linux-gnu-gcc powerpc64-linux-gnu-objcopy elf-linux-ppc64-64-be-callgraph

find "${out_dir}" -type f \( -name '*.elf' -o -name '*.debug' \) | sort
