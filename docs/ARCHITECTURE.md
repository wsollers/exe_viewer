# PE / ELF Explorer Architecture

This document describes the current shape of the project. It is intentionally
practical: the diagrams show how code and data move today, plus the provider
boundaries we are adding for assembler/decompiler/live-process work.

## Runtime Shape

```mermaid
flowchart LR
    user["User"]
    app["peelf_viewer<br/>Application"]
    ui["UiApp<br/>Dear ImGui panels"]
    model["BinaryModel<br/>loaded file bytes + parsed image"]
    core["peelf_core<br/>PE / ELF parsers"]
    disasm["Capstone wrapper<br/>Disassembler"]
    symbols["SymbolIndex<br/>parser symbols + debug symbols"]
    graph["CallGraph model<br/>entry / fan-out / CFG work"]
    graphviz["Graphviz dot<br/>external renderer"]
    vulkan["VulkanManager<br/>textures + ImGui backend"]

    user --> app
    app --> ui
    app --> model
    model --> core
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

## Panel Navigation Model

```mermaid
flowchart TD
    structure["Structure tree"]
    sections["Sections panel"]
    imports["Imports panel"]
    exports["Exports panel"]
    symbolsPanel["Symbols panel"]
    graphPanel["Call Graph panel"]

    selection["ViewerSelection<br/>kind, label, file offset, VA, size, preferred view"]

    details["Details panel"]
    hex["Hex View<br/>scroll + highlight byte range"]
    disasmPanel["Disassembly panel<br/>decode from mapped offset"]

    structure --> selection
    sections --> selection
    imports --> selection
    exports --> selection
    symbolsPanel --> selection
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
