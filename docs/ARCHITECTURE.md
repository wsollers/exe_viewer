# PE / ELF Explorer Architecture

This document describes the current shape of the project. It is intentionally
practical: the diagrams show how code and data move today, plus the provider
boundaries we are adding for assembler/decompiler/live-process work.

## Runtime Shape

```mermaid
flowchart LR
    user["User"]
    app["peelf_viewer<br/>Application"]
    ui["UiApp<br/>Dear ImGui panels + MemMap + Attach Modal"]
    model["BinaryModel<br/>static file OR live process session"]
    core["peelf_core<br/>PE / ELF parsers + live rebasing"]
    proc["IProcessBackend / IProcessSession<br/>Linux /proc + process_vm_* · Win32 Toolhelp + VirtualQueryEx"]
    patches["PagedBinaryImage / LiveMemoryPatchSpace<br/>stage-first overlay + explicit Commit/Revert RAM"]
    disasm["Capstone wrapper<br/>Disassembler"]
    symbols["SymbolIndex<br/>PE/ELF symbols + GOT/PLT + rebased PDB"]
    graph["CallGraph model<br/>entry / fan-out / CFG work"]
    graphviz["Graphviz dot<br/>external renderer"]
    vulkan["VulkanManager<br/>textures + ImGui backend"]

    user --> app
    app --> ui
    app --> model
    model --> core
    model --> proc
    model --> patches
    ui --> model
    ui --> disasm
    ui --> symbols
    ui --> graph
    graph --> graphviz
    graphviz --> graph
    graph --> vulkan
    ui --> vulkan
```

## Static File Load Flow

```mermaid
sequenceDiagram
    actor User
    participant App as Application
    participant Model as BinaryModel
    participant Core as peelf_core
    participant Ui as UiApp
    participant Symbols as SymbolIndex
    participant Disasm as Capstone Disassembler

    User->>App: File > Open
    App->>Model: load_file(path)
    Model->>Core: detect + parse PE/ELF bytes
    Core-->>Model: IBinaryImage + parsed structures
    App->>Ui: on_file_loaded()
    Ui->>Symbols: build(image)
    Ui->>Disasm: init(architecture, endianness)
    Ui->>Ui: build Structure tree
    Ui->>Ui: navigate Hex/Disassembly to entry point
```

## Live Process Attach, MemMap & Stage-to-RAM Flow

```mermaid
sequenceDiagram
    actor User
    participant Ui as UiApp / Panels
    participant Model as BinaryModel
    participant Proc as IProcessBackend / Session
    participant Core as peelf_core (Live Rebasing)
    participant Patch as LiveMemoryPatchSpace

    User->>Ui: File > Attach to Process...
    Ui->>Model: list_processes() / attach_process(pid)
    Model->>Proc: open_process(pid) + memory_regions() + modules()
    Model->>Core: load_live_module_image(main_module)
    Note over Core: Combines live RAM at runtime ASLR base<br/>with on-disk PE/ELF (.symtab/.strtab, directories)<br/>rebased by (live_base - static_base)
    Core-->>Model: Rebased IBinaryImage + SymbolIndex
    Ui->>Ui: Populate Memory Map, Structure, Symbols, Hex & Disassembly
    User->>Ui: Edit byte in Hex View or Stage Shellcode
    Ui->>Patch: stage_patch(session, va, bytes)
    Note over Patch: Overlay only — live process RAM untouched;<br/>visible immediately in Hex, Disasm & Patch Set
    User->>Ui: Click "Commit to RAM"
    Ui->>Patch: commit_to_process(session, options)
    Patch->>Proc: Snapshot original RAM + write_memory (COW / VirtualProtectEx fallback)
    User->>Ui: Click "Revert RAM"
    Ui->>Patch: revert_committed(session)
    Patch->>Proc: Restore snapshotted original RAM bytes
```

## Panel Navigation Model

```mermaid
flowchart TD
    structure["Structure tree<br/>File OR Process / Modules / Memory Map"]
    memmap["Memory Map panel<br/>VMMap regions + module selector"]
    sections["Sections panel"]
    imports["Imports panel"]
    exports["Exports panel"]
    symbolsPanel["Symbols panel<br/>source + VA + offset"]
    patchPanel["Patch Set panel<br/>staged + committed RAM"]
    graphPanel["Call Graph panel"]

    selection["ViewerSelection<br/>kind, label, window offset, VA, size, preferred view"]

    details["Details panel"]
    hex["Hex View<br/>VA/offset + inline edit + ?? unmapped + patch highlights"]
    disasmPanel["Disassembly panel<br/>symbol labels + staged/committed tint"]

    structure --> selection
    memmap --> selection
    sections --> selection
    imports --> selection
    exports --> selection
    symbolsPanel --> selection
    patchPanel --> selection
    graphPanel --> selection

    selection --> details
    selection --> hex
    selection --> disasmPanel
```

Selections are the core UI contract. A panel should update `ViewerSelection`
instead of directly rewriting unrelated panels. `UiApp` then maps the selection
to Details/Hex/Disassembly when readable bytes exist. Selections without readable
bytes should remain valid and display a clear "hex not available" style message
as that path is hardened.

## Call Graph Flow

```mermaid
flowchart LR
    image["IBinaryImage<br/>sections, imports, symbols"]
    bytes["file bytes"]
    symidx["SymbolIndex<br/>parser + PDB/DWARF future"]
    capstone["Capstone detail disassembly"]
    builder["Call graph builders<br/>entry sketch, symbol fan-out, CFG"]
    dot["DOT text"]
    plain["Graphviz plain layout"]
    bmp["BMP/SVG output"]
    panel["Call Graph panel<br/>draw + hit-test"]
    selection["ViewerSelection"]

    image --> builder
    bytes --> builder
    symidx --> builder
    capstone --> builder
    builder --> dot
    dot --> plain
    dot --> bmp
    plain --> panel
    bmp --> panel
    panel --> selection
```

The current UI renders a graph and uses Graphviz `plain` metadata for node
hit-testing. Clicking a function-like node updates the shared selection and can
queue a new fan-out graph rooted at that symbol. The next major step is richer
basic-block CFG construction and more precise indirect-call handling.

## Assembly / Patch Provider Direction

```mermaid
flowchart TD
    shellcode["Shellcode panel<br/>paste hex or assembly"]
    patch["Future patch editor<br/>staged edits"]
    request["AssembleRequest<br/>arch, mode, endian, syntax, base address, text"]
    manager["Assembler provider manager"]
    asmtk["AsmTK / AsmJit provider<br/>x86/x64 fast path"]
    llvm["LLVM MC provider<br/>external llvm-mc + objcopy first"]
    unavailable["Unavailable provider<br/>explicit unsupported result"]
    result["AssembleResult<br/>bytes or diagnostic"]
    hex["Hex output / staged patch bytes"]

    shellcode --> request
    patch --> request
    request --> manager
    manager --> asmtk
    manager --> llvm
    manager --> unavailable
    asmtk --> result
    llvm --> result
    unavailable --> result
    result --> hex
```

AsmJit/AsmTK is now available as `peelf::asmtk` and has a smoke test proving
x64 `nop; ret` assembly. The provider wrapper is still pending. Unsupported
architectures must return an explicit unsupported/unavailable result so the UI
can show a useful message instead of failing silently.

## Dependency Shape

```mermaid
flowchart LR
    cmake["CMake configure"]
    fetch["FetchContent"]
    system["System packages"]
    viewer["peelf_viewer"]
    tests["peelf_tests"]

    fetch --> glfw["GLFW"]
    fetch --> imgui["Dear ImGui docking pin"]
    fetch --> nfd["nativefiledialog-extended"]
    fetch --> capstone["Capstone"]
    fetch --> asmjit["AsmJit"]
    fetch --> asmtk["AsmTK local wrapper"]
    fetch --> graphvizsrc["Graphviz source<br/>optional"]

    system --> vulkan["Vulkan SDK / libvulkan-dev"]
    system --> dot["Graphviz dot executable<br/>optional but recommended"]

    glfw --> viewer
    imgui --> viewer
    nfd --> viewer
    capstone --> viewer
    asmjit --> asmtk
    asmtk --> viewer
    capstone --> tests
    asmtk --> tests
    vulkan --> viewer
    dot --> viewer
    graphvizsrc --> viewer
```

`peelf::asmtk` and `peelf::graphviz` are stable project-facing targets. Their
feature macros report whether the backing implementation/tool is available.

## Test Fixture Matrix

```mermaid
flowchart TD
    docker["Docker cross toolchain image"]
    generator["tests/fixtures/build_cross_callgraph_fixtures.sh"]
    matrix["bin-matrix/"]
    tests["GoogleTest matrix tests"]

    docker --> generator
    generator --> elf["ELF executables + .so<br/>x86, x86-64, ARM, ARM64, RISC-V64, MIPS, PowerPC"]
    generator --> pe["PE DLL fixtures<br/>x86, x86-64"]
    elf --> matrix
    pe --> matrix
    matrix --> tests
```

The checked-in `bin-matrix/` files let normal builds run parser, symbol,
disassembly, and call-graph tests without regenerating fixtures. The Docker
targets refresh the matrix when cross-toolchain coverage changes.
