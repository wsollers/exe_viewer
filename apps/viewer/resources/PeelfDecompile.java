// Export decompiled C with conservative, optional line-to-address mappings.
// @category PEELF
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class PeelfDecompile extends HeadlessScript {
    private record NamedSymbol(Address address, long size, boolean function, String name) {}
    private List<NamedSymbol> symbols = new ArrayList<>();
    private long functionSize = 0;
    private void applySymbol(NamedSymbol symbol) throws Exception {
        String name=symbol.name().replaceAll("\\s", "_");
        var function=getFunctionAt(symbol.address());
        try {
            if (function!=null && symbol.function()) {
                if (!function.getName().equals(name)) function.setName(name,SourceType.USER_DEFINED);
            } else {
                // The loader, PDB analyzer, or prepare pass may already own this label.
                for (var existing : currentProgram.getSymbolTable().getSymbols(symbol.address()))
                    if (existing.getName().equals(name)) return;
                createLabel(symbol.address(),name,true,SourceType.USER_DEFINED);
            }
        } catch (ghidra.util.exception.DuplicateNameException | ghidra.util.exception.InvalidInputException ignored) {
            // Names are best-effort annotations. Preserve the existing symbol and
            // function body when an alias conflicts; never fail decompilation for it.
        }
    }
    private String decode(String value) {
        return value.equals("-") ? "" : new String(HexFormat.of().parseHex(value), StandardCharsets.UTF_8);
    }
    private void readSymbols(Path path, boolean prepare) throws Exception {
        try (var input = new Scanner(path, StandardCharsets.UTF_8)) {
            if (!input.next().equals("PEELF_SYMBOLS") || input.nextInt()!=1) throw new IllegalArgumentException("Invalid symbol metadata");
            input.next(); functionSize=input.nextLong();
            int count=input.nextInt();
            if (count<0 || count>1000000) throw new IllegalArgumentException("Too many symbols");
            for (int i=0;i<count;i++) {
                Address address=currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.parseUnsignedLong(input.next()));
                long size=input.nextLong(); boolean function=input.nextInt()!=0; String name=decode(input.next());
                if (currentProgram.getMemory().contains(address)) symbols.add(new NamedSymbol(address,size,function,name));
            }
            int types=input.nextInt();
            if (types<0 || types>10000) throw new IllegalArgumentException("Too many structures");
            for (int t=0;t<types;t++) {
                String name=decode(input.next()); int size=input.nextInt(); boolean union=input.nextInt()!=0; int members=input.nextInt();
                if (size<0 || size>16777216 || members<0 || members>4096) throw new IllegalArgumentException("Invalid structure layout");
                Composite type=union ? new UnionDataType(name) : new StructureDataType(name,size);
                for (int m=0;m<members;m++) {
                    int offset=input.nextInt(), length=input.nextInt(); String field=decode(input.next()), display=decode(input.next());
                    if (!prepare || length<=0 || offset<0 || offset>size || length>size-offset || display.contains("bit field")) continue;
                    // Preserve known layout without inventing semantics for unknown member types.
                    DataType data=Undefined.getUndefinedDataType(length);
                    if (display.equals("int32_t") && length==4) data=IntegerDataType.dataType;
                    else if (display.equals("uint32_t") && length==4) data=UnsignedIntegerDataType.dataType;
                    else if (display.equals("float") && length==4) data=FloatDataType.dataType;
                    else if (display.equals("double") && length==8) data=DoubleDataType.dataType;
                    try {
                        if (type instanceof Structure structure) structure.replaceAtOffset(offset,data,length,field,display);
                        else ((Union)type).add(data,length,field,display);
                    } catch (IllegalArgumentException ignored) {
                        // Flattened PDB anonymous unions can have overlapping members.
                        // Retain the representable layout instead of aborting analysis.
                    }
                }
                if (prepare) currentProgram.getDataTypeManager().addDataType(type,DataTypeConflictHandler.KEEP_HANDLER);
            }
        }
        for (var symbol : symbols) applySymbol(symbol);
    }
    private String exportTypes() {
        var records=new ArrayList<String>();
        var types=currentProgram.getDataTypeManager().getAllDataTypes();
        while (types.hasNext() && records.size()<10000) {
            var type=types.next();
            if (!(type instanceof Composite composite) || type.getLength()<0 || type.getLength()>16777216) continue;
            var members=new ArrayList<String>();
            for (var field : composite.getDefinedComponents()) {
                if (field.getOffset()<0 || field.getLength()<0 || field.getOffset()+field.getLength()>type.getLength()) continue;
                members.add(field.getOffset()+" "+field.getLength()+" "+quote(String.valueOf(field.getFieldName()))+" "+quote(field.getDataType().getDisplayName()));
                if (members.size()>=4096) break;
            }
            records.add(quote(type.getName())+" "+type.getLength()+" "+(type instanceof Union ? 1 : 0)+" "+members.size()+"\n"+String.join("\n",members));
        }
        return records.size()+"\n"+String.join("\n",records)+"\n";
    }
    private String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace('\r', ' ').replace('\n', ' ').replace('\0', ' ') + "\"";
    }
    private void output(Path path, String status, String message, List<String> lines) throws Exception {
        String text = "PEELF_DECOMPILE 3\n" + status + " " + quote(message) + "\n"
            + lines.size() + "\n" + String.join("\n", lines) + "\n" + (status.equals("ready") ? exportTypes() : "0\n");
        if (text.getBytes(StandardCharsets.UTF_8).length > 4 * 1024 * 1024)
            text = "PEELF_DECOMPILE 2\nfailed \"Output exceeds 4 MiB\"\n0\n";
        Files.writeString(path, text, StandardCharsets.UTF_8);
    }
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 5) throw new IllegalArgumentException("Expected phase, output, address, Thumb mode, symbol metadata");
        Path destination = Path.of(args[1]);
        try {
            Address address = currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddress(Long.parseUnsignedLong(args[2]));
            readSymbols(Path.of(args[4]), args[0].equals("prepare"));
            if (args[0].equals("prepare")) {
                if (Boolean.parseBoolean(args[3])) {
                    var register = currentProgram.getRegister("TMode");
                    if (register == null) throw new IllegalArgumentException("Thumb mode is unavailable for this processor");
                    currentProgram.getProgramContext().setValue(register, address, address, BigInteger.ONE);
                }
                return;
            }
            if (Files.exists(destination)) return;
            if (analysisTimeoutOccurred()) {
                output(destination, "timeout", "Ghidra analysis timed out", List.of()); return;
            }
            var function = getFunctionContaining(address);
            if (functionSize>0) {
                var block=currentProgram.getMemory().getBlock(address);
                if (block==null || !block.isExecute() || functionSize-1>block.getEnd().subtract(address))
                    throw new IllegalArgumentException("Function bounds exceed executable memory");
                var body=new AddressSet(address,address.add(functionSize-1));
                for (var symbol : symbols) if (symbol.function() && symbol.size()>0 && !symbol.address().equals(address) && body.contains(symbol.address()))
                    throw new IllegalArgumentException("Function bounds overlap another named function");
                var manager=currentProgram.getFunctionManager();
                var overlaps=manager.getFunctionsOverlapping(body);
                var remove=new ArrayList<Address>();
                while (overlaps.hasNext()) {
                    var overlapping=overlaps.next();
                    if (!overlapping.getEntryPoint().equals(address)) remove.add(overlapping.getEntryPoint());
                }
                for (var entry : remove) manager.removeFunction(entry);
                disassemble(address);
                function=getFunctionAt(address);
                String name=symbols.stream().filter(s->s.address().equals(address) && s.function()).map(s->s.name().replaceAll("\\s","_")).findFirst().orElse(null);
                if (function==null) function=manager.createFunction(null,address,body,SourceType.USER_DEFINED);
                else function.setBody(body);
                if (name!=null) applySymbol(new NamedSymbol(address,functionSize,true,name));
            }
            if (function == null && currentProgram.getMemory().contains(address)) {
                disassemble(address);
                function = createFunction(address, null);
            }
            if (function == null) {
                output(destination, "no_function", "No function at selected address", List.of()); return;
            }
            var decompiler = new DecompInterface();
            try {
                if (!decompiler.openProgram(currentProgram)) {
                    output(destination, "unsupported", String.valueOf(decompiler.getLastMessage()), List.of()); return;
                }
                var result = decompiler.decompileFunction(function, 60, monitor);
                if (!result.decompileCompleted()) {
                    output(destination, result.isTimedOut() ? "timeout" : "failed", result.getErrorMessage(), List.of()); return;
                }
                var printer = new PrettyPrinter(function, result.getCCodeMarkup(), null);
                List<String> lines = new ArrayList<>();
                for (var line : printer.getLines()) {
                    var mapped = new TreeMap<Address,Integer>();
                    for (var token : line.getAllTokens()) {
                        var candidate = token.getMinAddress();
                        if (candidate != null && candidate.isMemoryAddress() && function.getBody().contains(candidate)) {
                            var instruction=getInstructionContaining(candidate);
                            if(instruction!=null) mapped.put(instruction.getAddress(),instruction.getLength());
                        }
                    }
                    var row=new StringBuilder().append(mapped.size());
                    for(var range : mapped.entrySet()) row.append(' ').append(Long.toUnsignedString(range.getKey().getOffset())).append(' ').append(range.getValue());
                    row.append(' ').append(quote(PrettyPrinter.getText(line))); lines.add(row.toString());
                    if (lines.size() > 100000) throw new IllegalStateException("Function exceeds line limit");
                }
                output(destination, "ready", "Decompiled C; line address mappings are approximate.", lines);
            } finally { decompiler.dispose(); }
        } catch (Exception error) {
            output(destination, "failed", String.valueOf(error.getMessage()), List.of());
        }
    }
}
