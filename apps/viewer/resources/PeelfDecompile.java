// Export decompiled C with conservative, optional line-to-address mappings.
// @category PEELF
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import java.math.BigInteger;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class PeelfDecompile extends HeadlessScript {
    private String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace('\r', ' ').replace('\n', ' ').replace('\0', ' ') + "\"";
    }
    private void output(Path path, String status, String message, List<String> lines) throws Exception {
        String text = "PEELF_DECOMPILE 2\n" + status + " " + quote(message) + "\n"
            + lines.size() + "\n" + String.join("\n", lines) + "\n";
        if (text.getBytes(StandardCharsets.UTF_8).length > 4 * 1024 * 1024)
            text = "PEELF_DECOMPILE 2\nfailed \"Output exceeds 4 MiB\"\n0\n";
        Files.writeString(path, text, StandardCharsets.UTF_8);
    }
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4) throw new IllegalArgumentException("Expected phase, output, address, Thumb mode");
        Path destination = Path.of(args[1]);
        try {
            Address address = currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddress(Long.parseUnsignedLong(args[2]));
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
                    Address mapped = null;
                    for (var token : line.getAllTokens()) {
                        var candidate = token.getMinAddress();
                        if (candidate != null && candidate.isMemoryAddress()) { mapped = candidate; break; }
                    }
                    lines.add((mapped == null ? "-" : Long.toUnsignedString(mapped.getOffset()))
                        + " " + quote(PrettyPrinter.getText(line)));
                    if (lines.size() > 100000) throw new IllegalStateException("Function exceeds line limit");
                }
                output(destination, "ready", "Decompiled C; line address mappings are approximate.", lines);
            } finally { decompiler.dispose(); }
        } catch (Exception error) {
            output(destination, "failed", String.valueOf(error.getMessage()), List.of());
        }
    }
}
