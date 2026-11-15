#include "decompiler.hpp"
#include "analysis/project.hpp"
#include <atomic>
#include <cstdlib>
#include <fstream>
#include <format>
#include <iomanip>
#include <sstream>

namespace viewer {
namespace {
bool installation(const std::filesystem::path& path) {
    std::error_code ec;
    return std::filesystem::is_regular_file(path / "Ghidra/Framework/Utility/lib/Utility.jar", ec);
}
std::filesystem::path environment(const char* name) {
#ifdef _WIN32
    char* value = nullptr; std::size_t size = 0;
    _dupenv_s(&value, &size, name);
    const std::filesystem::path result = value ? value : "";
    std::free(value); return result;
#else
    const auto* value = std::getenv(name);
    return value ? value : "";
#endif
}
}
DecompilerSettings discover_decompilers(const std::filesystem::path& directory) {
    DecompilerSettings settings;
    settings.ghidra_home = environment("GHIDRA_INSTALL_DIR");
    if (settings.ghidra_home.empty()) {
        for (auto parent = directory; !parent.empty(); parent = parent.parent_path()) {
            for (const auto& base : {parent / "tools", parent / "out/tools"}) {
                std::error_code ec;
                for (const auto& entry : std::filesystem::directory_iterator(base, ec)) {
                    if (installation(entry.path()) && entry.path() > settings.ghidra_home)
                        settings.ghidra_home = entry.path();
                }
            }
            if (!settings.ghidra_home.empty() || parent == parent.parent_path()) break;
        }
    }
    if (auto home = environment("JAVA_HOME"); !home.empty()) {
#ifdef _WIN32
        settings.java = home / "bin/java.exe";
#else
        settings.java = home / "bin/java";
#endif
    }
    return settings;
}
peelf::Result<DecompilerSettings> read_decompiler_settings(const std::filesystem::path& path) {
    auto text = read_project_file(path);
    if (!text) return std::unexpected(text.error());
    std::istringstream in(*text); std::string magic, home, java, python; int version = 0, provider = -1;
    DecompilerSettings settings;
    if (!(in >> magic >> version >> provider >> std::quoted(home) >> std::quoted(java) >> std::quoted(python) >> settings.timeout_seconds) ||
        magic != "PEELF_DECOMPILER" || version != 1 || provider < 0 || provider > 4 ||
        java.empty() || python.empty() || settings.timeout_seconds < 10 || settings.timeout_seconds > 3600)
        return peelf::make_error("Invalid decompiler settings");
    in >> std::ws;
    if (!in.eof()) return peelf::make_error("Unexpected trailing decompiler settings");
    settings.provider = static_cast<DecompilerProvider>(provider);
    settings.ghidra_home = home; settings.java = java; settings.python = python;
    return settings;
}
peelf::Result<void> save_decompiler_settings(const std::filesystem::path& path, const DecompilerSettings& settings) {
    std::ostringstream out;
    out << "PEELF_DECOMPILER 1\n" << static_cast<int>(settings.provider) << '\n'
        << std::quoted(settings.ghidra_home.string()) << '\n' << std::quoted(settings.java.string()) << '\n'
        << std::quoted(settings.python.string()) << '\n' << settings.timeout_seconds << '\n';
    return write_analysis_file(path, out.str());
}
DecompiledUnit GhidraDecompiler::decompile(const DecompileRequest& request, std::stop_token stop) const {
    auto failure = [](DecompileStatus status, std::string message) { return DecompiledUnit{status, "Ghidra", std::move(message)}; };
    if (stop.stop_requested()) return failure(DecompileStatus::Cancelled, "Decompilation cancelled");
    if (!installation(settings_.ghidra_home)) return failure(DecompileStatus::Unavailable, "Set the Ghidra installation directory (containing Ghidra and support folders).");
    if (!std::filesystem::is_regular_file(scripts_ / "PeelfDecompile.java"))
        return failure(DecompileStatus::Unavailable, "Ghidra bridge resource is missing");
    if (request.architecture == peelf::Architecture::Unknown) return failure(DecompileStatus::Unsupported, "Unknown CPU architecture");
    if (request.image_bytes.empty()) return failure(DecompileStatus::Failed, "Empty binary snapshot");
    if (settings_.timeout_seconds < 10 || settings_.timeout_seconds > 3600)
        return failure(DecompileStatus::Failed, "Timeout must be between 10 and 3600 seconds");
    static std::atomic<std::uint64_t> serial{};
    const auto directory = std::filesystem::temp_directory_path() / std::format("peelf-ghidra-{}-{}",
        std::chrono::steady_clock::now().time_since_epoch().count(), ++serial);
    std::error_code ec;
    if (!std::filesystem::create_directory(directory, ec)) return failure(DecompileStatus::Failed, "Cannot create Ghidra workspace");
    struct Workspace { std::filesystem::path path; ~Workspace() { std::error_code ignored; std::filesystem::remove_all(path, ignored); } } workspace{directory};
    const auto input = directory / "input.bin", output = directory / "result.txt";
    const auto metadata = directory / "symbols.txt";
    { std::ofstream file(metadata, std::ios::binary); file << encode_decompiler_symbols(request);
      file.close(); if (!file) return failure(DecompileStatus::Failed,"Cannot write symbol snapshot"); }
    { std::ofstream file(input, std::ios::binary);
      file.write(reinterpret_cast<const char*>(request.image_bytes.data()), static_cast<std::streamsize>(request.image_bytes.size()));
      file.close(); if (!file) return failure(DecompileStatus::Failed, "Cannot write binary snapshot"); }
    // Launch the same entry point as analyzeHeadless, without a command shell.
    std::vector<std::string> args{"-Xmx2G", "-Xshare:off", "-Djava.awt.headless=true",
        "-Djava.system.class.loader=ghidra.GhidraClassLoader", "-Dfile.encoding=UTF8",
        "-Duser.language=en", "-Duser.country=US", "--enable-native-access=ALL-UNNAMED",
        "-cp", (settings_.ghidra_home / "Ghidra/Framework/Utility/lib/Utility.jar").string(),
        "ghidra.Ghidra", "ghidra.app.util.headless.AnalyzeHeadless", directory.string(), "analysis",
        "-import", input.string(), "-scriptPath", scripts_.string(),
        "-preScript", "PeelfDecompile.java", "prepare", output.string(), std::to_string(request.address), request.thumb ? "true" : "false", metadata.string(),
        "-postScript", "PeelfDecompile.java", "export", output.string(), std::to_string(request.address), request.thumb ? "true" : "false", metadata.string(),
        "-analysisTimeoutPerFile", std::to_string(settings_.timeout_seconds), "-max-cpu", "2", "-deleteProject"};
    const auto result = runner_.run(settings_.java, args, std::chrono::seconds(settings_.timeout_seconds), stop);
    if (result.cancelled) return failure(DecompileStatus::Cancelled, "Decompilation cancelled");
    if (result.timed_out) return failure(DecompileStatus::Timeout, "Ghidra exceeded the configured deadline; increase the timeout for large binaries.");
    if (!std::filesystem::is_regular_file(output, ec))
        return failure(result.exit_code < 0 ? DecompileStatus::Unavailable : DecompileStatus::Failed,
            std::format("Ghidra produced no result (exit {}). Check the Java executable and Ghidra/JDK compatibility. Ghidra 12.2 requires JDK 25.", result.exit_code));
    const auto size = std::filesystem::file_size(output, ec);
    if (ec || size > 4 * 1024 * 1024) return failure(DecompileStatus::Failed, "Ghidra output exceeds 4 MiB");
    std::ifstream file(output, std::ios::binary); std::string text(static_cast<std::size_t>(size), '\0');
    if (!file.read(text.data(), static_cast<std::streamsize>(size))) return failure(DecompileStatus::Failed, "Cannot read Ghidra output");
    auto unit = parse_decompiler_output(text); unit.provider = "Ghidra";
    if (result.exit_code != 0 && unit.status == DecompileStatus::Ready)
        return failure(DecompileStatus::Failed, "Ghidra exited unsuccessfully; output discarded");
    return unit;
}
}
