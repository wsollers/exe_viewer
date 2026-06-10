#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_file="${script_dir}/cross_callgraph_fixture.c"
out_dir="${script_dir}/cross"

mkdir -p "${out_dir}"

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

aarch64-linux-gnu-gcc "${common_flags[@]}" "${source_file}" -o "${out_dir}/known-callgraph-aarch64.elf"
riscv64-linux-gnu-gcc \
  "${common_flags[@]}" \
  -march=rv64g \
  -mabi=lp64d \
  -mno-relax \
  "${source_file}" \
  -o "${out_dir}/known-callgraph-riscv64.elf"

chmod a-x "${out_dir}/known-callgraph-aarch64.elf" "${out_dir}/known-callgraph-riscv64.elf"
