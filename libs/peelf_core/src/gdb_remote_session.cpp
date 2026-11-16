#include <peelf/gdb_remote.hpp>

#include <algorithm>
#include <array>
#include <filesystem>
#include <mutex>
#include <utility>

namespace peelf {

namespace {

[[nodiscard]] std::optional<std::string_view> extract_stop_reply_thread_token(
    std::string_view stop_reply) noexcept {
    if (stop_reply.size() < 4u || stop_reply.front() != 'T') {
        return std::nullopt;
    }
    std::size_t pos = 3u;
    while (pos < stop_reply.size()) {
        const std::size_t semi = stop_reply.find(';', pos);
        if (semi == std::string_view::npos) {
            break;
        }
        const std::string_view kv = stop_reply.substr(pos, semi - pos);
        if (kv.starts_with("thread:") && kv.size() > 7u) {
            return kv.substr(7u);
        }
        pos = semi + 1u;
    }
    return std::nullopt;
}

[[nodiscard]] RspTargetDescription synthesize_fallback_target_description(
    Architecture arch,
    Endianness endian,
    AddressWidth width) {
    RspTargetDescription desc{};
    desc.architecture = arch;
    desc.endianness = endian;
    desc.address_width = width;
    desc.explicit_endianness = true;

    const auto add_reg = [&](std::string name,
                             std::uint32_t regnum,
                             std::uint32_t bitsize,
                             RegisterCategory cat) {
        desc.registers.push_back(RspRegisterSpec{
            .name = std::move(name),
            .regnum = regnum,
            .bitsize = bitsize,
            .type = "int",
            .group = "general",
            .feature_name = "fallback",
            .category = cat,
            .save_restore = true,
        });
    };

    switch (arch) {
        case Architecture::X86_64: {
            static constexpr std::array<std::string_view, 16> kGprs = {
                "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};
            for (std::uint32_t i = 0; i < kGprs.size(); ++i) {
                RegisterCategory cat = RegisterCategory::General;
                if (kGprs[i] == "rsp") {
                    cat = RegisterCategory::StackPointer;
                } else if (kGprs[i] == "rbp") {
                    cat = RegisterCategory::FramePointer;
                }
                add_reg(std::string(kGprs[i]), i, 64u, cat);
            }
            add_reg("rip", 16u, 64u, RegisterCategory::InstructionPointer);
            add_reg("eflags", 17u, 32u, RegisterCategory::Flags);
            break;
        }
        case Architecture::X86: {
            static constexpr std::array<std::string_view, 8> kGprs = {
                "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
            for (std::uint32_t i = 0; i < kGprs.size(); ++i) {
                RegisterCategory cat = RegisterCategory::General;
                if (kGprs[i] == "esp") {
                    cat = RegisterCategory::StackPointer;
                } else if (kGprs[i] == "ebp") {
                    cat = RegisterCategory::FramePointer;
                }
                add_reg(std::string(kGprs[i]), i, 32u, cat);
            }
            add_reg("eip", 8u, 32u, RegisterCategory::InstructionPointer);
            add_reg("eflags", 9u, 32u, RegisterCategory::Flags);
            break;
        }
        case Architecture::ARM64: {
            for (std::uint32_t i = 0; i < 31u; ++i) {
                const RegisterCategory cat =
                    (i == 29u) ? RegisterCategory::FramePointer : RegisterCategory::General;
                add_reg("x" + std::to_string(i), i, 64u, cat);
            }
            add_reg("sp", 31u, 64u, RegisterCategory::StackPointer);
            add_reg("pc", 32u, 64u, RegisterCategory::InstructionPointer);
            add_reg("cpsr", 33u, 32u, RegisterCategory::Flags);
            break;
        }
        case Architecture::ARM: {
            for (std::uint32_t i = 0; i < 13u; ++i) {
                const RegisterCategory cat =
                    (i == 11u) ? RegisterCategory::FramePointer : RegisterCategory::General;
                add_reg("r" + std::to_string(i), i, 32u, cat);
            }
            add_reg("sp", 13u, 32u, RegisterCategory::StackPointer);
            add_reg("lr", 14u, 32u, RegisterCategory::General);
            add_reg("pc", 15u, 32u, RegisterCategory::InstructionPointer);
            add_reg("cpsr", 25u, 32u, RegisterCategory::Flags);
            break;
        }
        case Architecture::RISCV64:
        case Architecture::RISCV32: {
            const std::uint32_t bits = (arch == Architecture::RISCV64) ? 64u : 32u;
            for (std::uint32_t i = 0; i < 32u; ++i) {
                RegisterCategory cat = RegisterCategory::General;
                if (i == 2u) {
                    cat = RegisterCategory::StackPointer;
                } else if (i == 8u) {
                    cat = RegisterCategory::FramePointer;
                } else if (i == 4u) {
                    cat = RegisterCategory::SegmentOrTls;
                }
                add_reg("x" + std::to_string(i), i, bits, cat);
            }
            add_reg("pc", 32u, bits, RegisterCategory::InstructionPointer);
            break;
        }
        default:
            break;
    }

    return desc;
}

void decode_architectural_flags(
    Architecture arch,
    const RspTargetDescription& desc,
    std::uint64_t flags_val,
    std::vector<FlagBitInfo>& out_flags) {
    if (!desc.flags_types.empty() && !desc.flags_types.front().fields.empty()) {
        for (const auto& f : desc.flags_types.front().fields) {
            if (f.start_bit == f.end_bit && f.start_bit < 64u) {
                out_flags.push_back(FlagBitInfo{
                    .name = f.name,
                    .bit = f.start_bit,
                    .set = ((flags_val >> f.start_bit) & 1ULL) != 0ULL,
                    .description = f.name,
                });
            }
        }
        if (!out_flags.empty()) {
            return;
        }
    }

    if (arch == Architecture::X86 || arch == Architecture::X86_64) {
        struct BitSpec {
            const char* name;
            std::uint8_t bit;
            const char* desc;
        };
        static constexpr std::array<BitSpec, 9> kX86Flags = {{
            {"CF", 0u, "Carry Flag"},
            {"PF", 2u, "Parity Flag"},
            {"AF", 4u, "Auxiliary Carry Flag"},
            {"ZF", 6u, "Zero Flag"},
            {"SF", 7u, "Sign Flag"},
            {"TF", 8u, "Trap Flag"},
            {"IF", 9u, "Interrupt Enable Flag"},
            {"DF", 10u, "Direction Flag"},
            {"OF", 11u, "Overflow Flag"},
        }};
        for (const auto& b : kX86Flags) {
            out_flags.push_back(FlagBitInfo{
                .name = b.name,
                .bit = b.bit,
                .set = ((flags_val >> b.bit) & 1ULL) != 0ULL,
                .description = b.desc,
            });
        }
    } else if (arch == Architecture::ARM || arch == Architecture::ARM64) {
        struct BitSpec {
            const char* name;
            std::uint8_t bit;
            const char* desc;
        };
        static constexpr std::array<BitSpec, 4> kArmFlags = {{
            {"N", 31u, "Negative Condition Flag"},
            {"Z", 30u, "Zero Condition Flag"},
            {"C", 29u, "Carry Condition Flag"},
            {"V", 28u, "Overflow Condition Flag"},
        }};
        for (const auto& b : kArmFlags) {
            out_flags.push_back(FlagBitInfo{
                .name = b.name,
                .bit = b.bit,
                .set = ((flags_val >> b.bit) & 1ULL) != 0ULL,
                .description = b.desc,
            });
        }
    }
}

[[nodiscard]] MemoryProtection parse_memory_map_protection(const RspMemoryMapEntry& entry) {
    if (!entry.permissions.empty()) {
        MemoryProtection prot{};
        for (const char ch : entry.permissions) {
            if (ch == 'r' || ch == 'R') {
                prot.readable = true;
            } else if (ch == 'w' || ch == 'W') {
                prot.writable = true;
            } else if (ch == 'x' || ch == 'X') {
                prot.executable = true;
            }
        }
        return prot;
    }

    switch (entry.type) {
        case RspMemoryRegionType::Ram:
            return MemoryProtection{.readable = true, .writable = true, .executable = true};
        case RspMemoryRegionType::Rom:
        case RspMemoryRegionType::Flash:
            return MemoryProtection{.readable = true, .writable = false, .executable = true};
        case RspMemoryRegionType::Unknown:
            return MemoryProtection{.readable = true, .writable = false, .executable = false};
    }
    return MemoryProtection{.readable = true, .writable = false, .executable = false};
}

class GdbRemoteReadOnlySession final : public IGdbRemoteSession {
public:
    explicit GdbRemoteReadOnlySession(RspClient client) : client_(std::move(client)) {
        client_.set_read_only_mode(true);
    }

    [[nodiscard]] Result<void> initialize(
        const GdbRemoteOpenOptions& options,
        std::stop_token stop_token) {
        client_.set_read_only_mode(true);

        auto caps_res = client_.negotiate(stop_token);
        if (!caps_res) {
            return std::unexpected(caps_res.error());
        }

        std::optional<RspRemoteThreadId> stop_reply_tid{};
        if (auto halt_reply = client_.send_command("?", stop_token); halt_reply.has_value()) {
            halted_at_open_ = !halt_reply->empty() &&
                              (halt_reply->front() == 'S' || halt_reply->front() == 'T');
            if (const auto tok = extract_stop_reply_thread_token(*halt_reply); tok.has_value()) {
                if (auto parsed = parse_rsp_thread_id(*tok);
                    parsed.has_value() && parsed->is_concrete_thread()) {
                    stop_reply_tid = std::move(*parsed);
                }
            }
        }

        std::optional<RspTargetDescription> negotiated_desc{};
        if (caps_res->qxfer_features_read) {
            auto td = client_.read_target_description(stop_token);
            if (!td) {
                return std::unexpected(td.error());
            }
            negotiated_desc = std::move(*td);
        }

        if (negotiated_desc.has_value()) {
            target_desc_ = std::move(*negotiated_desc);
        } else {
            const Architecture fb_arch = options.fallback_architecture.value_or(Architecture::Unknown);
            const bool is32 = fb_arch == Architecture::X86 || fb_arch == Architecture::ARM ||
                              fb_arch == Architecture::RISCV32 || fb_arch == Architecture::PowerPC ||
                              fb_arch == Architecture::MIPS32;
            const bool default_be = fb_arch == Architecture::PowerPC ||
                                    fb_arch == Architecture::PowerPC64 ||
                                    fb_arch == Architecture::MIPS32 ||
                                    fb_arch == Architecture::MIPS64;
            const Endianness fb_endian = options.fallback_endianness.value_or(
                default_be ? Endianness::Big : Endianness::Little);
            const AddressWidth fb_width = options.fallback_address_width.value_or(
                is32 ? AddressWidth::Bits32 : AddressWidth::Bits64);
            target_desc_ = synthesize_fallback_target_description(fb_arch, fb_endian, fb_width);
        }

        if (caps_res->qxfer_auxv_read) {
            if (auto auxv_str = client_.read_qxfer("auxv", "", stop_token);
                auxv_str.has_value() && auxv_str->has_value() && !(*auxv_str)->empty()) {
                const std::string& raw = **auxv_str;
                cached_auxv_.emplace(
                    reinterpret_cast<const std::uint8_t*>(raw.data()),
                    reinterpret_cast<const std::uint8_t*>(raw.data()) + raw.size());
            }
        }

        if (auto initial_threads = client_.enumerate_threads(stop_token);
            initial_threads.has_value()) {
            for (const auto& t : *initial_threads) {
                (void)tid_mapper_.intern(t);
            }
        }
        if (stop_reply_tid.has_value()) {
            fallback_thread_ = *stop_reply_tid;
            if (tid_mapper_.size() == 0u) {
                (void)tid_mapper_.intern(*stop_reply_tid);
            }
        }
        if (tid_mapper_.size() == 0u) {
            // Bare-metal single-core stubs may omit both qfThreadInfo and qC.
            RspRemoteThreadId fallback_core{};
            fallback_core.multiprocess = false;
            fallback_core.pid_kind = RspIdKind::Any;
            fallback_core.pid = 0u;
            fallback_core.tid_kind = RspIdKind::Explicit;
            fallback_core.tid = 1u;
            fallback_core.wire_token = "1";
            fallback_thread_ = fallback_core;
            (void)tid_mapper_.intern(fallback_core);
        }

        std::optional<std::vector<RspLibraryEntry>> initial_libs{};
        if (caps_res->qxfer_libraries_svr4_read || caps_res->qxfer_libraries_read) {
            if (auto libs = client_.read_libraries(stop_token);
                libs.has_value() && libs->has_value()) {
                initial_libs = std::move(**libs);
            }
        }

        populate_profile_and_process_info(initial_libs);
        return {};
    }

    [[nodiscard]] const ProcessInfo& info() const noexcept override { return process_info_; }

    [[nodiscard]] bool is_alive() const noexcept override { return client_.is_open(); }
    [[nodiscard]] bool is_read_only() const noexcept override { return true; }
    [[nodiscard]] bool is_crash_dump() const noexcept override { return false; }
    [[nodiscard]] bool is_suspended() const noexcept override {
        return halted_at_open_ && client_.is_open();
    }

    [[nodiscard]] TargetLayout target_layout() const noexcept override {
        return TargetLayout{
            .architecture = target_profile_.architecture,
            .address_width = target_profile_.address_width,
            .endianness = target_profile_.endianness,
        };
    }

    [[nodiscard]] const TargetProfile& target_profile() const noexcept override {
        return target_profile_;
    }

    [[nodiscard]] const ProviderFacts& provider_facts() const noexcept override {
        return provider_facts_;
    }

    [[nodiscard]] TargetCapabilityMatrix capability_matrix() const override {
        return capabilities_for(target_profile_, provider_facts_);
    }

    [[nodiscard]] const RspCapabilities& rsp_capabilities() const noexcept override {
        return client_.capabilities();
    }

    [[nodiscard]] const RspTargetDescription& target_description() const noexcept override {
        return target_desc_;
    }

    [[nodiscard]] Result<std::size_t> write_memory(
        std::uint64_t /*address*/,
        std::span<const std::uint8_t> /*data*/,
        MemoryWriteOptions /*options*/ = {}) override {
        return make_error(
            "GdbRemoteBackend::open_read_only session is strictly read-only; write_memory is forbidden");
    }

    [[nodiscard]] Result<void> suspend() override {
        return make_error("GDB remote read-only session does not alter target execution state");
    }

    [[nodiscard]] Result<void> resume() override {
        return make_error("GDB remote read-only session does not alter target execution state");
    }

    [[nodiscard]] Result<void> suspend_thread(ThreadId /*tid*/) override {
        return make_error("GDB remote read-only session does not alter thread execution state");
    }

    [[nodiscard]] Result<void> resume_thread(ThreadId /*tid*/) override {
        return make_error("GDB remote read-only session does not alter thread execution state");
    }

    [[nodiscard]] Result<std::size_t> read_memory(
        std::uint64_t address,
        std::span<std::uint8_t> buffer) override {
        const std::scoped_lock lock(mutex_);
        return client_.read_memory(address, buffer);
    }

    [[nodiscard]] Result<std::vector<MemoryRegion>> memory_regions() override {
        const std::scoped_lock lock(mutex_);

        if (client_.capabilities().qxfer_memory_map_read) {
            auto mmap_res = client_.read_memory_map();
            if (!mmap_res) {
                return std::unexpected(mmap_res.error());
            }
            if (mmap_res->has_value() && !(*mmap_res)->empty()) {
                std::vector<MemoryRegion> out;
                out.reserve((*mmap_res)->size());
                for (const auto& entry : **mmap_res) {
                    const auto end_addr = checked_add_u64(entry.start, entry.length);
                    if (!end_addr.has_value() || *end_addr <= entry.start) {
                        continue;
                    }
                    MemoryRegion reg{};
                    reg.start_address = entry.start;
                    reg.end_address = *end_addr;
                    reg.protection = parse_memory_map_protection(entry);
                    reg.kind = (entry.type == RspMemoryRegionType::Rom ||
                                entry.type == RspMemoryRegionType::Flash)
                                   ? MemoryRegionKind::Image
                                   : MemoryRegionKind::Anonymous;
                    reg.pathname = !entry.name.empty()
                                       ? entry.name
                                       : ("[" + std::string(to_string(entry.type)) + "]");
                    reg.usage.committed_bytes = entry.length;
                    reg.usage.vm_flags = std::string(to_string(entry.type));
                    out.push_back(std::move(reg));
                }
                std::ranges::sort(out, {}, &MemoryRegion::start_address);
                return out;
            }
        }

        // Fallback for QEMU user-mode stubs that omit qXfer:memory-map:read but expose AT_PHDR in auxv.
        if (cached_auxv_.has_value() && !cached_auxv_->empty()) {
            auto auxv_regions = probe_elf_pt_load_regions_from_auxv_locked(*cached_auxv_);
            if (!auxv_regions.empty()) {
                return auxv_regions;
            }
        }

        // Minimal bare-metal / QEMU stub without memory-map XML: degrade gracefully with empty region list.
        return std::vector<MemoryRegion>{};
    }

    [[nodiscard]] Result<std::vector<ModuleInfo>> modules() override {
        const std::scoped_lock lock(mutex_);

        if (!client_.capabilities().qxfer_libraries_svr4_read &&
            !client_.capabilities().qxfer_libraries_read) {
            return std::vector<ModuleInfo>{};
        }

        auto libs_res = client_.read_libraries();
        if (!libs_res) {
            return std::unexpected(libs_res.error());
        }
        if (!libs_res->has_value()) {
            return std::vector<ModuleInfo>{};
        }

        std::vector<ModuleInfo> mods;
        mods.reserve((*libs_res)->size());
        for (const auto& lib : **libs_res) {
            ModuleInfo mod{};
            mod.path = std::filesystem::path(lib.name);
            mod.name = mod.path.filename().string();
            if (mod.name.empty()) {
                mod.name = !lib.name.empty()
                               ? lib.name
                               : (lib.is_main_module ? "[main]" : "[remote-module]");
            }
            mod.base_address = lib.base_address;
            mod.is_main_module = lib.is_main_module;
            mod.format = client_.capabilities().qxfer_libraries_svr4_read
                             ? Format::ELF
                             : target_profile_.format;

            if (mod.base_address != 0u) {
                probe_module_header_locked(mod);
            }
            mods.push_back(std::move(mod));
        }
        return mods;
    }

    [[nodiscard]] Result<std::vector<ThreadInfo>> threads() override {
        const std::scoped_lock lock(mutex_);

        auto remote_threads = client_.enumerate_threads();
        if (!remote_threads) {
            return std::unexpected(remote_threads.error());
        }

        std::vector<RspRemoteThreadId> list = std::move(*remote_threads);
        if (list.empty() && fallback_thread_.has_value()) {
            list.push_back(*fallback_thread_);
        }

        std::vector<ThreadInfo> out;
        out.reserve(list.size());
        for (const auto& rt : list) {
            const ThreadId local_tid = tid_mapper_.intern(rt);
            ThreadInfo ti{};
            ti.tid = local_tid;
            ti.name = rt.wire_token;
            ti.state = halted_at_open_ ? ThreadRunState::Stopped : ThreadRunState::Running;
            ti.is_suspended = halted_at_open_;
            ti.status = SubsystemStatus::available("gdb_rsp", "Remote thread " + rt.wire_token);
            out.push_back(std::move(ti));
        }
        return out;
    }

    [[nodiscard]] std::optional<RspRemoteThreadId> resolve_remote_thread_id(
        ThreadId local_tid) const override {
        const std::scoped_lock lock(mutex_);
        return tid_mapper_.lookup_remote(local_tid);
    }

    [[nodiscard]] Result<std::vector<RspRegisterValue>> read_thread_registers(
        ThreadId local_tid) override {
        const std::scoped_lock lock(mutex_);
        return read_thread_registers_locked(local_tid);
    }

    [[nodiscard]] ThreadContext thread_context(ThreadId tid) override {
        const std::scoped_lock lock(mutex_);

        ThreadContext ctx{};
        ctx.tid = tid;
        ctx.layout = target_layout();

        auto regs_res = read_thread_registers_locked(tid);
        if (!regs_res) {
            ctx.status = SubsystemStatus::unavailable("gdb_rsp", regs_res.error().message);
            return ctx;
        }

        std::size_t avail_count = 0;
        std::size_t missing_count = 0;
        ctx.registers.reserve(regs_res->size());

        for (const auto& rr : *regs_res) {
            if (rr.is_available()) {
                ++avail_count;
            } else {
                ++missing_count;
            }

            if (rr.is_available() && rr.value_u64.has_value()) {
                const std::uint64_t v = *rr.value_u64;
                if (rr.category == RegisterCategory::InstructionPointer &&
                    ctx.instruction_pointer == 0u) {
                    ctx.instruction_pointer = v;
                } else if (rr.category == RegisterCategory::StackPointer &&
                           ctx.stack_pointer == 0u) {
                    ctx.stack_pointer = v;
                } else if (rr.category == RegisterCategory::FramePointer &&
                           ctx.frame_pointer == 0u) {
                    ctx.frame_pointer = v;
                } else if (rr.category == RegisterCategory::Flags &&
                           !ctx.flags_value.has_value()) {
                    ctx.flags_value = v;
                } else if ((rr.name == "lr" || rr.name == "x30" || rr.name == "ra" ||
                            rr.name == "r31" || rr.name == "$31") &&
                           !ctx.link_register.has_value()) {
                    ctx.link_register = v;
                } else if ((rr.name == "fs_base" || rr.name == "tp" || rr.name == "tpidr_el0" ||
                            rr.name == "tpidr") &&
                           !ctx.tls_pointer.has_value()) {
                    ctx.tls_pointer = v;
                }
            }

            RegisterValue rv{};
            rv.name = rr.name;
            rv.category = rr.category;
            rv.bit_width = rr.bit_width;
            rv.value_u64 = rr.is_available() ? rr.value_u64.value_or(0u) : 0u;
            if (rr.is_available()) {
                rv.raw_bytes = rr.raw_bytes;
            }
            rv.formatted = rr.formatted;
            ctx.registers.push_back(std::move(rv));
        }

        if (ctx.flags_value.has_value()) {
            decode_architectural_flags(
                target_profile_.architecture, target_desc_, *ctx.flags_value, ctx.decoded_flags);
        }

        if (avail_count == 0u) {
            ctx.status = SubsystemStatus::unavailable(
                "gdb_rsp",
                "All registers in GDB RSP reply were marked unavailable ('xx') or omitted");
        } else if (missing_count > 0u) {
            ctx.status = SubsystemStatus::partial(
                "gdb_rsp",
                std::to_string(missing_count) +
                    " register(s) reported unavailable ('xx') or partial by GDB RSP stub");
        } else {
            ctx.status = SubsystemStatus::available("gdb_rsp", "GDB RSP register frame decoded");
        }
        return ctx;
    }

    [[nodiscard]] ProcessInternalsSnapshot process_internals() const override {
        ProcessInternalsSnapshot snap{};
        const bool bare_metal = (target_profile_.os == OsKind::BareMetal);
        const std::string reason =
            bare_metal
                ? "OS kernel tables do not exist on bare-metal / QEMU system-mode GDB target"
                : "GDB RSP read-only session does not expose remote OS handle/socket/credential tables";
        snap.handles.status = SubsystemStatus::unavailable("gdb_rsp", reason);
        snap.sockets.status = SubsystemStatus::unavailable("gdb_rsp", reason);
        snap.security.status = SubsystemStatus::unavailable("gdb_rsp", reason);
        return snap;
    }

private:
    void populate_profile_and_process_info(
        const std::optional<std::vector<RspLibraryEntry>>& initial_libs) {
        target_profile_.backend = BackendKind::GdbRemote;
        target_profile_.architecture = target_desc_.architecture;
        target_profile_.endianness = target_desc_.endianness;
        target_profile_.address_width = target_desc_.address_width;

        const bool has_elf_os_evidence =
            (cached_auxv_.has_value() && !cached_auxv_->empty()) ||
            client_.capabilities().qxfer_libraries_svr4_read;

        if (target_desc_.os != OsKind::Unknown) {
            target_profile_.os = target_desc_.os;
            target_profile_.abi = target_desc_.abi;
        } else if (has_elf_os_evidence) {
            target_profile_.os = OsKind::Linux;
            target_profile_.abi = AbiKind::GnuLinux;
        } else {
            // Bare-metal / QEMU system-mode stub with no OS ABI or SVR4/auxv runtime tables.
            target_profile_.os = OsKind::BareMetal;
            target_profile_.abi = AbiKind::Standalone;
        }

        if (target_profile_.os == OsKind::Windows) {
            target_profile_.format = Format::PE;
            target_profile_.image_kind = ImageKind::Executable;
        } else if (has_elf_os_evidence ||
                   (target_profile_.os != OsKind::BareMetal &&
                    target_profile_.os != OsKind::Unknown)) {
            target_profile_.format = Format::ELF;
            target_profile_.image_kind = ImageKind::Executable;
        } else {
            target_profile_.format = Format::Unknown;
            target_profile_.image_kind = ImageKind::Unknown;
        }

        provider_facts_ = ProviderFacts::detect_host_providers();
        provider_facts_.remote_gdb_stub_available = true;

        const std::uint64_t raw_pid = tid_mapper_.primary_pid();
        process_info_.pid = (raw_pid > 0u && raw_pid <= 0xFFFF'FFFFu)
                                ? static_cast<ProcessId>(raw_pid)
                                : ProcessId{1u};
        process_info_.architecture = target_profile_.architecture;
        process_info_.endianness = target_profile_.endianness;
        process_info_.is_64bit = (target_profile_.address_width == AddressWidth::Bits64);
        process_info_.access = ProcessAccessStatus::ReadOnly;
        process_info_.name = "gdb-remote (" + client_.endpoint_description() + ")";

        if (initial_libs.has_value()) {
            for (const auto& lib : *initial_libs) {
                if (lib.is_main_module && !lib.name.empty()) {
                    process_info_.executable_path = std::filesystem::path(lib.name);
                    const std::string fname = process_info_.executable_path.filename().string();
                    if (!fname.empty()) {
                        process_info_.name = fname;
                    }
                    break;
                }
            }
        }
    }

    [[nodiscard]] Result<std::vector<RspRegisterValue>> read_thread_registers_locked(
        ThreadId local_tid) {
        if (target_desc_.registers.empty()) {
            return make_error("GDB RSP target description contains zero register definitions");
        }

        auto remote_tid = tid_mapper_.lookup_remote(local_tid);
        if (!remote_tid.has_value()) {
            if (auto refreshed = client_.enumerate_threads(); refreshed.has_value()) {
                for (const auto& rt : *refreshed) {
                    (void)tid_mapper_.intern(rt);
                }
            }
            remote_tid = tid_mapper_.lookup_remote(local_tid);
        }
        if (!remote_tid.has_value()) {
            return make_error("Unknown GDB RSP thread ID " + std::to_string(local_tid));
        }

        if (auto sel = client_.select_general_thread(remote_tid->wire_token); !sel) {
            return std::unexpected(sel.error());
        }
        return client_.read_all_registers(target_desc_);
    }

    void probe_module_header_locked(ModuleInfo& mod) {
        std::array<std::uint8_t, 64> hdr{};
        auto n = client_.read_memory(mod.base_address, hdr);
        if (!n.has_value() || *n < 4u) {
            return;
        }
        if (hdr[0] == 0x7Fu && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F') {
            mod.format = Format::ELF;
            if (*n >= 32u) {
                const EndianReader er(
                    std::span<const std::uint8_t>(hdr.data(), *n), target_layout());
                if (target_layout().is_64bit()) {
                    mod.entry_point = er.read_u64(24u).value_or(0u);
                } else {
                    mod.entry_point = er.read_u32(24u).value_or(0u);
                }
            }
        } else if (hdr[0] == 'M' && hdr[1] == 'Z') {
            mod.format = Format::PE;
        }
    }

    [[nodiscard]] std::vector<MemoryRegion> probe_elf_pt_load_regions_from_auxv_locked(
        std::span<const std::uint8_t> auxv_bytes) {
        const TargetLayout layout = target_layout();
        const std::size_t word_sz = layout.pointer_size();
        const std::size_t pair_sz = word_sz * 2u;
        if (auxv_bytes.size() < pair_sz) {
            return {};
        }

        const EndianReader er(auxv_bytes, layout);
        std::uint64_t at_phdr = 0;
        std::uint64_t at_phent = 0;
        std::uint64_t at_phnum = 0;
        std::uint64_t at_pagesz = 4096u;

        for (std::size_t off = 0; off + pair_sz <= auxv_bytes.size(); off += pair_sz) {
            const auto tag = er.read_pointer(off);
            const auto val = er.read_pointer(off + word_sz);
            if (!tag.has_value() || !val.has_value() || *tag == 0u) {
                break;
            }
            switch (*tag) {
                case 3u: at_phdr = *val; break;    // AT_PHDR
                case 4u: at_phent = *val; break;   // AT_PHENT
                case 5u: at_phnum = *val; break;   // AT_PHNUM
                case 6u:
                    if (*val >= 512u && (*val & (*val - 1u)) == 0u) {
                        at_pagesz = *val;
                    }
                    break;
                default:
                    break;
            }
        }

        const std::size_t expected_phent = layout.is_64bit() ? 56u : 32u;
        if (at_phdr == 0u || at_phent < expected_phent || at_phent > 128u ||
            at_phnum == 0u || at_phnum > 256u) {
            return {};
        }

        const auto total_ph_bytes = checked_mul_u64(at_phent, at_phnum);
        if (!total_ph_bytes.has_value() || *total_ph_bytes > 32768u) {
            return {};
        }

        std::vector<std::uint8_t> ph_buf(static_cast<std::size_t>(*total_ph_bytes));
        auto got = client_.read_memory(at_phdr, ph_buf);
        if (!got.has_value() || *got < ph_buf.size()) {
            return {};
        }

        const EndianReader ph_er(ph_buf, layout);
        std::optional<std::uint64_t> load_bias{};

        for (std::uint64_t i = 0; i < at_phnum; ++i) {
            const auto off = static_cast<std::size_t>(i * at_phent);
            const std::uint32_t p_type = ph_er.read_u32(off).value_or(0u);
            if (p_type == 6u) {  // PT_PHDR
                const std::uint64_t p_vaddr = layout.is_64bit()
                                                  ? ph_er.read_u64(off + 16u).value_or(0u)
                                                  : ph_er.read_u32(off + 8u).value_or(0u);
                if (at_phdr >= p_vaddr) {
                    load_bias = at_phdr - p_vaddr;
                }
                break;
            }
        }

        if (!load_bias.has_value()) {
            for (std::uint64_t i = 0; i < at_phnum; ++i) {
                const auto off = static_cast<std::size_t>(i * at_phent);
                const std::uint32_t p_type = ph_er.read_u32(off).value_or(0u);
                if (p_type != 1u) {
                    continue;
                }
                const std::uint64_t p_offset = layout.is_64bit()
                                                   ? ph_er.read_u64(off + 8u).value_or(1u)
                                                   : ph_er.read_u32(off + 4u).value_or(1u);
                const std::uint64_t p_vaddr = layout.is_64bit()
                                                  ? ph_er.read_u64(off + 16u).value_or(0u)
                                                  : ph_er.read_u32(off + 8u).value_or(0u);
                const std::uint64_t ehdr_phoff = layout.is_64bit() ? 64u : 52u;
                if (p_offset == 0u && at_phdr >= p_vaddr + ehdr_phoff) {
                    load_bias = at_phdr - (p_vaddr + ehdr_phoff);
                    break;
                }
            }
        }
        const std::uint64_t bias = load_bias.value_or(0u);
        const std::uint64_t page_mask = ~(at_pagesz - 1u);

        std::vector<MemoryRegion> regions;
        for (std::uint64_t i = 0; i < at_phnum; ++i) {
            const auto off = static_cast<std::size_t>(i * at_phent);
            const std::uint32_t p_type = ph_er.read_u32(off).value_or(0u);
            if (p_type != 1u) {  // PT_LOAD
                continue;
            }
            const std::uint32_t p_flags = layout.is_64bit()
                                              ? ph_er.read_u32(off + 4u).value_or(0u)
                                              : ph_er.read_u32(off + 24u).value_or(0u);
            const std::uint64_t p_offset = layout.is_64bit()
                                               ? ph_er.read_u64(off + 8u).value_or(0u)
                                               : ph_er.read_u32(off + 4u).value_or(0u);
            const std::uint64_t p_vaddr = layout.is_64bit()
                                              ? ph_er.read_u64(off + 16u).value_or(0u)
                                              : ph_er.read_u32(off + 8u).value_or(0u);
            const std::uint64_t p_memsz = layout.is_64bit()
                                              ? ph_er.read_u64(off + 40u).value_or(0u)
                                              : ph_er.read_u32(off + 20u).value_or(0u);
            if (p_memsz == 0u) {
                continue;
            }

            const auto biased_start = checked_add_u64(p_vaddr, bias);
            if (!biased_start.has_value()) {
                continue;
            }
            const auto raw_end = checked_add_u64(*biased_start, p_memsz);
            if (!raw_end.has_value()) {
                continue;
            }
            const std::uint64_t aligned_start = *biased_start & page_mask;
            const auto padded_end = checked_add_u64(*raw_end, at_pagesz - 1u);
            const std::uint64_t aligned_end =
                padded_end.has_value() ? (*padded_end & page_mask) : *raw_end;
            if (aligned_end <= aligned_start) {
                continue;
            }

            MemoryRegion reg{};
            reg.start_address = aligned_start;
            reg.end_address = aligned_end;
            reg.protection.readable = (p_flags & 0x4u) != 0u;
            reg.protection.writable = (p_flags & 0x2u) != 0u;
            reg.protection.executable = (p_flags & 0x1u) != 0u;
            reg.kind = MemoryRegionKind::Image;
            reg.file_offset = p_offset & page_mask;
            reg.pathname = process_info_.executable_path.empty()
                               ? "[auxv:PT_LOAD]"
                               : process_info_.executable_path.string();
            reg.module_name = process_info_.name;
            reg.usage.committed_bytes = aligned_end - aligned_start;
            reg.usage.vm_flags = "auxv:PT_LOAD";
            regions.push_back(std::move(reg));
        }

        std::ranges::sort(regions, {}, &MemoryRegion::start_address);
        return regions;
    }

    mutable std::mutex mutex_{};
    RspClient client_;
    ProcessInfo process_info_{};
    TargetProfile target_profile_{};
    ProviderFacts provider_facts_{};
    RspTargetDescription target_desc_{};
    RspThreadIdMapper tid_mapper_{};
    std::optional<RspRemoteThreadId> fallback_thread_{};
    std::optional<std::vector<std::uint8_t>> cached_auxv_{};
    bool halted_at_open_{true};
};

}  // namespace

// ---------------------------------------------------------------------------
// GdbRemoteBackend entry points
// ---------------------------------------------------------------------------

Result<std::unique_ptr<IProcessSession>> GdbRemoteBackend::open_read_only(
    std::unique_ptr<IRspTransport> transport,
    const GdbRemoteOpenOptions& options,
    std::stop_token stop_token) {
    if (transport == nullptr || !transport->is_open()) {
        return make_error("GdbRemoteBackend::open_read_only requires an open IRspTransport");
    }

    RspClientOptions client_opts = options.rsp;
    client_opts.strict_read_only = true;

    RspClient client(std::move(transport), client_opts);
    auto session = std::make_unique<GdbRemoteReadOnlySession>(std::move(client));
    if (auto init_res = session->initialize(options, stop_token); !init_res) {
        return std::unexpected(init_res.error());
    }
    return session;
}

Result<std::unique_ptr<IProcessSession>> GdbRemoteBackend::open_read_only(
    const GdbRemoteOpenOptions& options,
    std::stop_token stop_token) {
    auto transport = TcpRspTransport::connect(options.endpoint, stop_token);
    if (!transport) {
        return std::unexpected(transport.error());
    }
    return open_read_only(std::move(*transport), options, stop_token);
}

Result<std::unique_ptr<IProcessSession>> GdbRemoteBackend::open_read_only(
    const RemoteEndpointOptions& endpoint,
    std::stop_token stop_token) {
    GdbRemoteOpenOptions opts{};
    opts.endpoint = endpoint;
    opts.rsp.command_timeout = endpoint.io_timeout;
    return open_read_only(opts, stop_token);
}

Result<std::unique_ptr<IProcessSession>> GdbRemoteBackend::open_read_only(
    std::string_view endpoint_spec,
    bool allow_unencrypted_remote_endpoint,
    std::stop_token stop_token) {
    RemoteEndpointOptions defaults{};
    defaults.allow_unencrypted_remote_endpoint = allow_unencrypted_remote_endpoint;
    auto parsed = parse_gdb_remote_endpoint(endpoint_spec, defaults);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    return open_read_only(*parsed, stop_token);
}

}  // namespace peelf
