# Test fixtures

Small binary samples used by the unit tests.

## Files

- `hello.elf` — a 64-bit, little-endian, PIE ELF executable, dynamically linked
  against `libc.so.6` and **not stripped** (so it carries a real symbol table with
  `main` and `add`). Built from a trivial in-house C source, so it is license-clean
  to commit. Good for exercising ELF header parsing, program headers/sections,
  dynamic symbols/imports, and x86-64 disassembly.
- `known-linux-x64.elf` — deterministic minimal ELF64 executable fixture with a
  `.text` section, one `PT_INTERP` interpreter path, one `_start` function
  symbol, one `DT_NEEDED` library, one `.rela.dyn` relocation, one `.note.peelf`
  note also covered by `PT_NOTE`, and `EM_X86_64`.
- `known-linux-arm64.elf` — deterministic minimal ELF64 executable fixture with a
  `.text` section, one `PT_INTERP` interpreter path, one `_start` function
  symbol, one `DT_NEEDED` library, one `.rela.dyn` relocation, one `.note.peelf`
  note also covered by `PT_NOTE`, and `EM_AARCH64`.
- `known-linux-riscv64.elf` — deterministic minimal ELF64 executable fixture with a
  `.text` section, one `PT_INTERP` interpreter path, one `_start` function
  symbol, one `DT_NEEDED` library, one `.rela.dyn` relocation, one `.note.peelf`
  note also covered by `PT_NOTE`, and `EM_RISCV`.
- `known-linux-x86-elf32-le.elf` — deterministic minimal ELF32 little-endian executable
  fixture with a `.text` section, one load segment, one `PT_INTERP` interpreter
  path, one `_start` function symbol, one `DT_NEEDED` library, one `.rel.dyn`
  relocation, one `.note.peelf` note also covered by `PT_NOTE`, and `EM_386`.
- `known-linux-mips-elf32-be.elf` — deterministic minimal ELF32 big-endian executable
  fixture with a `.text` section, one load segment, one `PT_INTERP` interpreter
  path, one `_start` function symbol, one `DT_NEEDED` library, one `.rel.dyn`
  relocation, one `.note.peelf` note also covered by `PT_NOTE`, and `EM_MIPS`.
- `known-linux-mips64-elf64-be.elf` — deterministic minimal ELF64 big-endian executable
  fixture with a `.text` section, one load segment, one `PT_INTERP` interpreter
  path, one `_start` function symbol, one `DT_NEEDED` library, one `.rela.dyn`
  relocation, one `.note.peelf` note also covered by `PT_NOTE`, and `EM_MIPS`.
- `known-linux-arm-elf32-le.elf` — deterministic minimal ELF32 little-endian executable
  fixture with a `.text` section, one load segment, one `PT_INTERP` interpreter
  path, one `_start` function symbol, one `DT_NEEDED` library, one `.rel.dyn`
  relocation, one `.note.peelf` note also covered by `PT_NOTE`, and `EM_ARM`.
- `known-linux-arm-elf32-be.elf` — deterministic minimal ELF32 big-endian executable
  fixture with a `.text` section, one load segment, one `PT_INTERP` interpreter
  path, one `_start` function symbol, one `DT_NEEDED` library, one `.rel.dyn`
  relocation, one `.note.peelf` note also covered by `PT_NOTE`, and `EM_ARM`.
- `known-linux-arm64-elf64-be.elf` — deterministic minimal ELF64 big-endian executable
  fixture with a `.text` section, one load segment, one `PT_INTERP` interpreter
  path, one `_start` function symbol, one `DT_NEEDED` library, one `.rela.dyn`
  relocation, one `.note.peelf` note also covered by `PT_NOTE`, and `EM_AARCH64`.
- `known-linux-riscv32-elf32-le.elf` — deterministic minimal ELF32 little-endian
  executable fixture with a `.text` section, one load segment, one `PT_INTERP`
  interpreter path, one `_start` function symbol, one `DT_NEEDED` library, one
  `.rel.dyn` relocation, one `.note.peelf` note also covered by `PT_NOTE`, and
  `EM_RISCV`.
- `known-linux-riscv32-elf32-be.elf` — deterministic minimal ELF32 big-endian
  executable fixture with a `.text` section, one load segment, one `PT_INTERP`
  interpreter path, one `_start` function symbol, one `DT_NEEDED` library, one
  `.rel.dyn` relocation, one `.note.peelf` note also covered by `PT_NOTE`, and
  `EM_RISCV`.
- `known-linux-riscv64-elf64-be.elf` — deterministic minimal ELF64 big-endian
  executable fixture with a `.text` section, one load segment, one `PT_INTERP`
  interpreter path, one `_start` function symbol, one `DT_NEEDED` library, one
  `.rela.dyn` relocation, one `.note.peelf` note also covered by `PT_NOTE`, and
  `EM_RISCV`.
- `known-linux-ppc-elf32-be.elf` — deterministic minimal ELF32 big-endian executable
  fixture with a `.text` section, one load segment, one `PT_INTERP` interpreter
  path, one `_start` function symbol, one `DT_NEEDED` library, one `.rel.dyn`
  relocation, one `.note.peelf` note also covered by `PT_NOTE`, and `EM_PPC`.
- `known-linux-ppc64-elf64-be.elf` — deterministic minimal ELF64 big-endian executable
  fixture with a `.text` section, one load segment, one `PT_INTERP` interpreter
  path, one `_start` function symbol, one `DT_NEEDED` library, one `.rela.dyn`
  relocation, one `.note.peelf` note also covered by `PT_NOTE`, and `EM_PPC64`.
- `known-win-x86.exe` — deterministic minimal PE32 executable fixture with `.text`,
  `.reloc`, `.debug`, and `.tls` sections, one HIGHLOW base relocation, one
  CodeView RSDS debug record, one runtime-function entry in the exception
  directory, one delay-load import (`USER32.dll!MessageBoxA`), one bound import
  record (`BOUND32.dll`), one top-level resource directory, one CLR header, one
  TLS directory with one callback, one overlay certificate table entry, one Load
  Config directory with Guard CF fields, and `IMAGE_FILE_MACHINE_I386`.
- `known-win-x64.exe` — deterministic minimal PE32+ executable fixture with a
  `.text` section, one import `KERNEL32.dll!ExitProcess`, one export named `known_export`,
  one `.reloc` section with a DIR64 base relocation, one `.debug` section with a
  CodeView RSDS debug record, one runtime-function entry in the exception
  directory, one delay-load import (`USER32.dll!MessageBoxA`), one bound import
  record (`BOUND64.dll`), one top-level resource directory, one CLR header, one
  `.tls` section with one TLS directory/callback, one overlay certificate table
  entry, one Load Config directory with Guard CF fields, and `IMAGE_FILE_MACHINE_AMD64`.
- `make_known_fixtures.ps1` — regenerates the `known-*` binary fixtures from
  explicit fixed-width field writes.

> If `hello.elf` is not present, the `ElfFixture.HasElfMagic` test will *skip*
> rather than fail. Drop the file provided alongside this work into this directory
> to activate it.

## Adding more fixtures

Prefer small, license-clean samples (compile your own where possible). Suggested
additions as parsing features land:

- a PE `.dll` (32-bit and 64-bit)
- a stripped ELF
- truncated / corrupt inputs for negative tests

Keep individual fixtures small and document what each one is for here.
Keep fixture files non-executable in git (`100644`).
