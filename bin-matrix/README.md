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
