# Test fixtures

Small binary samples used by the unit tests.

## Files

- `hello.elf` — a 64-bit, little-endian, PIE ELF executable, dynamically linked
  against `libc.so.6` and **not stripped** (so it carries a real symbol table with
  `main` and `add`). Built from a trivial in-house C source, so it is license-clean
  to commit. Good for exercising ELF header parsing, program headers/sections,
  dynamic symbols/imports, and x86-64 disassembly.
- `known-linux-x64.elf` — deterministic minimal ELF64 executable fixture with a
  `.text` section and `EM_X86_64`.
- `known-linux-arm64.elf` — deterministic minimal ELF64 executable fixture with a
  `.text` section and `EM_AARCH64`.
- `known-linux-riscv64.elf` — deterministic minimal ELF64 executable fixture with a
  `.text` section and `EM_RISCV`.
- `known-win-x64.exe` — deterministic minimal PE32+ executable fixture with a
  `.text` section and `IMAGE_FILE_MACHINE_AMD64`.
- `make_known_fixtures.ps1` — regenerates the four `known-*` binary fixtures from
  explicit fixed-width field writes.

> If `hello.elf` is not present, the `ElfFixture.HasElfMagic` test will *skip*
> rather than fail. Drop the file provided alongside this work into this directory
> to activate it.

## Adding more fixtures

Prefer small, license-clean samples (compile your own where possible). Suggested
additions as parsing features land:

- a PE `.exe` and a PE `.dll` (32-bit and 64-bit)
- a stripped ELF and a big-endian ELF
- truncated / corrupt inputs for negative tests

Keep individual fixtures small and document what each one is for here.
Keep fixture files non-executable in git (`100644`).
