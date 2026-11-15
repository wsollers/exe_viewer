#include "decompiler.hpp"
#include <peelf/sha256.hpp>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <format>
#include <thread>
#include <atomic>
#include <charconv>
#include <cerrno>
#include <limits>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#endif

namespace viewer {
DecompiledUnit AnnotatedCodeDecompiler::decompile(const DecompileRequest& request, std::stop_token stop) const {
    DecompiledUnit unit{DecompileStatus::Ready,"Annotated code (not decompiled)","Instruction semantics are not lifted to C. Select Ghidra or Binary Ninja for decompilation."};
    for (const auto& node : request.fallback_graph.nodes) {
        if (stop.stop_requested()) { unit.status=DecompileStatus::Cancelled; unit.lines.clear(); return unit; }
        if (node.instructions.empty()) continue;
        unit.lines.push_back({node.bytes.start.virtual_address,node.label + ":"});
        for (const auto& instruction : node.instructions)
            unit.lines.push_back({instruction.address, std::format("    {} {}",instruction.mnemonic,instruction.operands)});
        for (const auto& edge : request.fallback_graph.edges) if (edge.from_node_id == node.id)
            unit.lines.push_back({std::nullopt,"    // " + edge.label + " -> " + edge.to_node_id});
    }
    if (unit.lines.empty()) { unit.status=DecompileStatus::NoFunction; unit.diagnostic="No decoded function is available"; }
    return unit;
}
DecompiledUnit parse_decompiler_output(std::string_view text) {
    DecompiledUnit unit; unit.provider="Binary Ninja HLIL";
    if (text.size()>4*1024*1024) { unit.diagnostic="Backend output exceeds 4 MiB"; return unit; }
    std::istringstream in{std::string(text)}; std::string magic,status; int version;
    const auto read_unsigned = [&in](std::uint64_t& value) {
        std::string token;
        if (!(in >> token)) return false;
        const auto [end, error] = std::from_chars(token.data(), token.data()+token.size(), value);
        return error == std::errc{} && end == token.data()+token.size();
    };
    if (!(in>>magic>>version>>status>>std::quoted(unit.diagnostic)) || magic!="PEELF_DECOMPILE" || version<1 || version>3) { unit.diagnostic="Malformed backend response"; return unit; }
    if (status=="unavailable") unit.status=DecompileStatus::Unavailable;
    else if (status=="unsupported") unit.status=DecompileStatus::Unsupported;
    else if (status=="no_function") unit.status=DecompileStatus::NoFunction;
    else if (status=="failed") unit.status=DecompileStatus::Failed;
    else if (status=="ready") unit.status=DecompileStatus::Ready;
    else if (status=="timeout") unit.status=DecompileStatus::Timeout;
    else { unit.diagnostic="Unknown backend status"; return unit; }
    std::size_t count;
    if (!(in>>count) || count>100000) { unit.status=DecompileStatus::Failed; unit.diagnostic="Invalid backend line count"; return unit; }
    for (std::size_t i=0;i<count;++i) {
        if (version == 3) {
            DecompiledLine line; std::size_t ranges=0;
            if (!(in>>ranges) || ranges>4096) return {DecompileStatus::Failed,unit.provider,"Invalid code range count"};
            for (std::size_t r=0;r<ranges;++r) {
                CodeRange range;
                if (!read_unsigned(range.address) || !read_unsigned(range.size) || !range.size || range.size>1048576 ||
                    range.address>std::numeric_limits<std::uint64_t>::max()-range.size)
                    return {DecompileStatus::Failed,unit.provider,"Invalid code byte range"};
                line.ranges.push_back(range);
            }
            if (!(in>>std::quoted(line.text))) return {DecompileStatus::Failed,unit.provider,"Truncated code line"};
            if (!line.ranges.empty()) line.address=line.ranges.front().address;
            unit.lines.push_back(std::move(line)); continue;
        }
        std::string address, line;
        if (!(in>>address>>std::quoted(line))) { unit.status=DecompileStatus::Failed; unit.diagnostic="Truncated backend lines"; unit.lines.clear(); return unit; }
        std::optional<std::uint64_t> mapped;
        if (address != "-" || version != 2) {
            std::uint64_t value{};
            const auto [end, error] = std::from_chars(address.data(), address.data()+address.size(), value);
            if (error != std::errc{} || end != address.data()+address.size()) {
                unit.status=DecompileStatus::Failed; unit.diagnostic="Invalid backend address"; unit.lines.clear(); return unit;
            }
            mapped = value;
        }
        unit.lines.push_back({mapped,std::move(line)});
    }
    if (version == 3) {
        std::size_t types=0;
        if (!(in>>types) || types>10000) return {DecompileStatus::Failed,unit.provider,"Invalid structure count"};
        for (std::size_t t=0;t<types;++t) {
            DataTypeRecord type; std::size_t members=0;
            if (!(in>>std::quoted(type.name)>>type.size>>type.is_union>>members) || members>4096 || type.size>16777216)
                return {DecompileStatus::Failed,unit.provider,"Invalid structure record"};
            for (std::size_t m=0;m<members;++m) {
                DataMember member;
                if (!(in>>member.offset>>member.size>>std::quoted(member.name)>>std::quoted(member.type)) ||
                    member.offset>type.size || member.size>type.size-member.offset)
                    return {DecompileStatus::Failed,unit.provider,"Invalid structure member"};
                type.members.push_back(std::move(member));
            }
            unit.types.push_back(std::move(type));
        }
    }
    in>>std::ws;
    if (!in.eof() || (unit.status==DecompileStatus::Ready && unit.lines.empty())) { unit.status=DecompileStatus::Failed; unit.diagnostic="Invalid backend response"; unit.lines.clear(); }
    return unit;
}
BackendProcessResult BackendRunner::run(const std::filesystem::path& executable, const std::vector<std::string>& arguments,
    std::chrono::milliseconds timeout,std::stop_token stop) const {
    if(stop.stop_requested()) return {-1,false,true};
#ifdef _WIN32
    auto quote=[](const std::wstring& value) {
        std::wstring output=L"\""; std::size_t slashes=0;
        for(auto c:value) { if(c==L'\\') { ++slashes; continue; } output.append(slashes*(c==L'"'?2:1),L'\\'); slashes=0; if(c==L'"') output+=L'\\'; output+=c; }
        output.append(slashes*2,L'\\'); output+=L'"'; return output;
    };
    auto command=quote(executable.wstring());
    for(const auto& arg:arguments) { command+=L' '; command+=quote(std::filesystem::path(arg).wstring()); }
    STARTUPINFOW startup{}; startup.cb=sizeof(startup); PROCESS_INFORMATION process{};
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (!job) return {};
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) { CloseHandle(job); return {}; }
    if(!CreateProcessW(nullptr,command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW | CREATE_SUSPENDED,nullptr,nullptr,&startup,&process)) { CloseHandle(job); return {}; }
    if (!AssignProcessToJobObject(job, process.hProcess) || ResumeThread(process.hThread) == static_cast<DWORD>(-1)) {
        TerminateProcess(process.hProcess, 1); CloseHandle(process.hThread); CloseHandle(process.hProcess); CloseHandle(job); return {};
    }
    CloseHandle(process.hThread);
    auto deadline=std::chrono::steady_clock::now()+timeout; BackendProcessResult result;
    while(WaitForSingleObject(process.hProcess,25)==WAIT_TIMEOUT) {
        if(stop.stop_requested() || std::chrono::steady_clock::now()>=deadline) {
            result.cancelled=stop.stop_requested(); result.timed_out=!result.cancelled;
            TerminateJobObject(job,1); WaitForSingleObject(process.hProcess,5000); CloseHandle(process.hProcess); CloseHandle(job); return result;
        }
    }
    DWORD exit=1; GetExitCodeProcess(process.hProcess,&exit); CloseHandle(process.hProcess); CloseHandle(job); result.exit_code=static_cast<int>(exit); return result;
#else
    std::vector<std::string> owned{executable.string()}; owned.insert(owned.end(),arguments.begin(),arguments.end());
    std::vector<char*> argv; for(auto& s:owned) argv.push_back(s.data()); argv.push_back(nullptr);
    const auto pid=fork(); if(pid<0) return {};
    if(pid==0) { setpgid(0,0); execvp(argv[0],argv.data()); _exit(127); }
    setpgid(pid,pid);
    auto deadline=std::chrono::steady_clock::now()+timeout; int status=0;
    for (;;) {
        const auto waited = waitpid(pid,&status,WNOHANG);
        if (waited == pid) break;
        if (waited < 0 && errno != EINTR) { kill(-pid,SIGKILL); return {}; }
        if(stop.stop_requested() || std::chrono::steady_clock::now()>=deadline) {
            kill(-pid,SIGKILL);
            while (waitpid(pid,&status,0) < 0 && errno == EINTR) {}
            return {-1,!stop.stop_requested(),stop.stop_requested()};
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    kill(-pid,SIGKILL);
    return {WIFEXITED(status)?WEXITSTATUS(status):-1};
#endif
}
DecompiledUnit BinaryNinjaDecompiler::decompile(const DecompileRequest& request,std::stop_token stop) const {
    auto failure=[](DecompileStatus status,std::string message) { return DecompiledUnit{status,"Binary Ninja HLIL",std::move(message)}; };
    if (!std::filesystem::is_regular_file(bridge_)) return failure(DecompileStatus::Unavailable,"Binary Ninja bridge resource is missing");
    if (request.architecture==peelf::Architecture::Unknown) return failure(DecompileStatus::Unsupported,"Unknown architecture");
    static std::atomic<std::uint64_t> serial{};
    auto directory=std::filesystem::temp_directory_path()/std::format("peelf-decompile-{}-{}",std::chrono::steady_clock::now().time_since_epoch().count(),++serial);
    std::error_code ec; if(!std::filesystem::create_directory(directory,ec)) return failure(DecompileStatus::Failed,"Cannot create backend workspace");
    struct Cleanup { std::filesystem::path path; ~Cleanup() { std::error_code ignored; std::filesystem::remove_all(path,ignored); } } cleanup{directory};
    const auto input=directory/"input.bin", output=directory/"output.txt";
    { std::ofstream file(input,std::ios::binary); file.write(reinterpret_cast<const char*>(request.image_bytes.data()),static_cast<std::streamsize>(request.image_bytes.size())); if(!file) return failure(DecompileStatus::Failed,"Cannot write analysis snapshot"); }
    const auto process=runner_.run(python_,{bridge_.string(),input.string(),output.string(),std::to_string(request.address)},std::chrono::seconds(60),stop);
    if(process.cancelled) return failure(DecompileStatus::Cancelled,"Decompilation cancelled");
    if(process.timed_out) return failure(DecompileStatus::Timeout,"Backend exceeded 60-second deadline");
    if(!std::filesystem::exists(output)) return failure(DecompileStatus::Unavailable,"Could not run Python bridge. Configure Python with the Binary Ninja API installed.");
    const auto size=std::filesystem::file_size(output,ec);
    if(ec || size>4*1024*1024) return failure(DecompileStatus::Failed,"Invalid backend output size");
    std::ifstream file(output,std::ios::binary); std::string text(static_cast<std::size_t>(size),'\0');
    if(!file.read(text.data(),static_cast<std::streamsize>(size))) return failure(DecompileStatus::Failed,"Cannot read backend output");
    return parse_decompiler_output(text);
}

std::string compute_decompiler_settings_fingerprint(const DecompilerSettings& settings) {
    peelf::Sha256Hasher hasher;
    const auto feed = [&hasher](std::string_view sv) {
        hasher.update(sv);
        hasher.update(std::string_view{"\0", 1});
    };
    feed(std::to_string(static_cast<int>(settings.provider)));
    switch (settings.provider) {
        case DecompilerProvider::Ghidra:
            feed(settings.ghidra_home.string());
            feed(settings.java.string());
            break;
        case DecompilerProvider::BinaryNinja:
            feed(settings.python.string());
            break;
        case DecompilerProvider::RetDec:
            feed(settings.retdec.string());
            break;
        case DecompilerProvider::AnnotatedCode:
        case DecompilerProvider::StructuredPseudoC:
            break;
    }
    return hasher.finalize_hex();
}

DecompileCacheKey make_decompile_cache_key(const DecompileRequest& request,
                                           const DecompilerSettings& settings) {
    std::string sha = request.binary_sha256;
    if (sha.empty() && !request.image_bytes.empty()) {
        sha = peelf::sha256_hex(request.image_bytes);
    }
    return DecompileCacheKey{
        .binary_sha256 = std::move(sha),
        .patch_revision = request.patch_revision,
        .symbol_revision = request.symbol_revision,
        .symbols_sha256 = compute_decompiler_symbols_digest(request.symbols, request.types),
        .provider = settings.provider,
        .settings_fingerprint = compute_decompiler_settings_fingerprint(settings),
        .architecture = request.architecture,
        .endianness = request.endianness,
        .thumb = request.thumb,
        .function_address = request.address,
        .function_size = request.function_size,
    };
}

std::optional<DecompiledUnit> DecompileCache::get(const DecompileCacheKey& key) const {
    if (key.binary_sha256.empty()) {
        return std::nullopt;
    }
    std::scoped_lock lock(mutex_);
    const auto it = index_.find(key);
    if (it == index_.end()) {
        return std::nullopt;
    }
    lru_.splice(lru_.begin(), lru_, it->second);
    DecompiledUnit copy = it->second->unit;
    copy.cache_source = DecompileCacheSource::MemoryCacheHit;
    return copy;
}

void DecompileCache::put(const DecompileCacheKey& key, DecompiledUnit unit) {
    if (key.binary_sha256.empty() || unit.status != DecompileStatus::Ready) {
        return;
    }
    std::scoped_lock lock(mutex_);
    if (const auto it = index_.find(key); it != index_.end()) {
        it->second->unit = std::move(unit);
        lru_.splice(lru_.begin(), lru_, it->second);
        return;
    }
    while (lru_.size() >= max_entries_) {
        index_.erase(lru_.back().key);
        lru_.pop_back();
    }
    lru_.push_front(Entry{.key = key, .unit = std::move(unit)});
    index_.emplace(lru_.front().key, lru_.begin());
}

void DecompileCache::invalidate_function(std::string_view binary_sha256,
                                         std::uint64_t function_address) {
    std::scoped_lock lock(mutex_);
    for (auto it = lru_.begin(); it != lru_.end();) {
        if (it->key.binary_sha256 == binary_sha256 &&
            it->key.function_address == function_address) {
            index_.erase(it->key);
            it = lru_.erase(it);
        } else {
            ++it;
        }
    }
}

void DecompileCache::invalidate_binary(std::string_view binary_sha256) {
    std::scoped_lock lock(mutex_);
    for (auto it = lru_.begin(); it != lru_.end();) {
        if (it->key.binary_sha256 == binary_sha256) {
            index_.erase(it->key);
            it = lru_.erase(it);
        } else {
            ++it;
        }
    }
}

void DecompileCache::clear() {
    std::scoped_lock lock(mutex_);
    index_.clear();
    lru_.clear();
}

std::size_t DecompileCache::size() const {
    std::scoped_lock lock(mutex_);
    return lru_.size();
}
}
