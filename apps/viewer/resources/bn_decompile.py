"""Optional Binary Ninja bridge. Uses a local installation; never executes the input binary.

API reference: https://docs.binary.ninja/dev/cookbook.html#il-decompilation
The GUI runs this process with a deadline and an isolated effective-byte snapshot.
Emits PEELF_DECOMPILE 3 (multi-range HLIL line mappings + exported structs/unions)
and supports --probe for non-destructive edition/license/architecture discovery.
"""
from __future__ import annotations

import argparse
from contextlib import nullcontext
from pathlib import Path
import sys

UINT64_MAX = (1 << 64) - 1
MAX_OUTPUT_BYTES = 4 * 1024 * 1024 - 4096
MAX_LINES = 100000
MAX_RANGES_PER_LINE = 4096
MAX_RANGE_SIZE = 1048576
MAX_TYPES = 10000
MAX_TYPE_SIZE = 16777216
MAX_TYPE_MEMBERS = 4096

ARCH_ALIASES = {
    'x86': {'x86', 'i386', 'ia32'},
    'x86_64': {'x86_64', 'x64', 'amd64'},
    'arm32': {'armv7', 'armv7eb', 'thumb2', 'thumb2eb', 'arm', 'arm32'},
    'arm64': {'aarch64', 'arm64', 'arm64e'},
    'mips32': {'mips32', 'mipsel32'},
    'mips64': {'mips64', 'mipsel64'},
    'ppc32': {'ppc', 'ppc_le', 'ppc32', 'powerpc'},
    'ppc64': {'ppc64', 'ppc64_le', 'powerpc64'},
    'riscv32': {'rv32gc', 'riscv32'},
    'riscv64': {'rv64gc', 'riscv64'},
}


def quoted(value) -> str:
    text = str(value).replace('\\', '\\\\').replace('"', '\\"').replace('\r', ' ').replace('\n', ' ')
    return f'"{text}"'


def configure_bn_home(bn_home: str | Path | None) -> str:
    if not bn_home:
        return ''
    base = Path(bn_home)
    if base.is_file():
        base = base.parent
    candidates = [
        base / 'python',
        base,
        base.parent / 'Resources' / 'python',
        base / 'Contents' / 'Resources' / 'python',
    ]
    chosen = ''
    for cand in candidates:
        try:
            if (cand / 'binaryninja' / '__init__.py').is_file():
                resolved = str(cand)
                if resolved not in sys.path:
                    sys.path.insert(0, resolved)
                if not chosen:
                    chosen = resolved
        except OSError:
            continue
    return chosen


def classify_edition(text: str) -> str:
    lower = (text or '').strip().lower()
    if not lower:
        return 'Unknown'
    if 'ultimate' in lower:
        return 'Ultimate'
    if 'headless' in lower:
        return 'Headless'
    if 'commercial' in lower or 'enterprise' in lower:
        return 'Commercial'
    if 'personal' in lower or 'non-commercial' in lower or 'student' in lower:
        return 'Personal'
    if 'free' in lower or 'demo' in lower:
        return 'Free'
    return 'Unknown'


def is_license_or_free_error(exc: BaseException) -> bool:
    msg = str(exc).lower()
    return any(
        token in msg
        for token in (
            'binary ninja free',
            'headless',
            'license',
            'commercial',
            'personal',
            'demo edition',
            'not supported in free',
        )
    )


def enumerate_bn_architectures(bn) -> list[str]:
    arch_cls = getattr(bn, 'Architecture', None)
    if arch_cls is None:
        return []
    names: list[str] = []
    try:
        for item in list(arch_cls)[:512]:
            name = str(getattr(item, 'name', item)).strip()
            if name and name not in names:
                names.append(name)
    except TypeError:
        pass
    return names


def write_probe_result(
    destination: str | Path,
    api_available: bool,
    headless_ok: bool,
    edition: str,
    version: str,
    py_dir: str,
    arches: list[str],
    diagnostic: str,
) -> None:
    bounded_arches = arches[:512]
    with Path(destination).open('w', encoding='utf-8', newline='\n') as out:
        out.write(
            f'PEELF_BN_PROBE 1\n'
            f'{1 if api_available else 0} {1 if headless_ok else 0} '
            f'{quoted(edition)} {quoted(version)} {quoted(py_dir)}\n'
            f'{len(bounded_arches)}\n'
        )
        for arch_name in bounded_arches:
            out.write(f'{quoted(arch_name)}\n')
        out.write(f'{quoted(diagnostic)}\n')


def run_probe(destination: str | Path, bn_home: str | Path | None = None) -> None:
    hinted_py_dir = configure_bn_home(bn_home)
    try:
        import binaryninja as bn
        if bn is None:
            raise ImportError('binaryninja module is None')
    except Exception as exc:
        if is_license_or_free_error(exc):
            edition = 'Free' if 'free' in str(exc).lower() else 'Unknown'
            write_probe_result(
                destination,
                api_available=True,
                headless_ok=False,
                edition=edition,
                version='',
                py_dir=hinted_py_dir,
                arches=['x86', 'x86_64'] if edition == 'Free' else [],
                diagnostic=(
                    f'Binary Ninja headless Python API is restricted ({exc}). '
                    'Headless batch decompilation requires Personal, Commercial, Ultimate, or Headless.'
                ),
            )
        else:
            write_probe_result(
                destination,
                api_available=False,
                headless_ok=False,
                edition='Unknown',
                version='',
                py_dir=hinted_py_dir,
                arches=[],
                diagnostic=f'Binary Ninja Python API is not installed in this interpreter ({exc}).',
            )
        return

    py_dir = hinted_py_dir
    bn_file = getattr(bn, '__file__', None)
    if bn_file:
        try:
            py_dir = str(Path(bn_file).resolve().parent.parent)
        except OSError:
            pass

    version = ''
    if callable(getattr(bn, 'core_version', None)):
        try:
            version = str(bn.core_version() or '')
        except Exception:
            version = ''

    product = ''
    if callable(getattr(bn, 'core_product', None)):
        try:
            product = str(bn.core_product() or '')
        except Exception:
            product = ''
    edition = classify_edition(product)
    arches = enumerate_bn_architectures(bn)

    if edition == 'Free':
        write_probe_result(
            destination,
            api_available=True,
            headless_ok=False,
            edition='Free',
            version=version,
            py_dir=py_dir,
            arches=['x86', 'x86_64'],
            diagnostic=(
                'Binary Ninja Free detected (interactive x86/x64 edition). '
                'Headless Python batch API and ARM64/ARM32/MIPS/PowerPC/RISC-V require '
                'Personal, Commercial, or Ultimate.'
            ),
        )
        return

    headless_ok = True
    diagnostic = 'Binary Ninja headless Python API ready.'
    load_fn = getattr(bn, 'load', None)
    if not callable(load_fn):
        headless_ok = False
        diagnostic = 'binaryninja.load() is unavailable in this installation.'
    else:
        probe_fn = getattr(bn, 'core_ui_enabled', None)
        if callable(probe_fn):
            try:
                _ = probe_fn()
            except Exception as exc:
                if is_license_or_free_error(exc):
                    headless_ok = False
                    if 'free' in str(exc).lower():
                        edition = 'Free'
                    diagnostic = f'Binary Ninja headless license check failed: {exc}'

    write_probe_result(
        destination,
        api_available=True,
        headless_ok=headless_ok,
        edition=edition,
        version=version,
        py_dir=py_dir,
        arches=arches,
        diagnostic=diagnostic,
    )


def write_result(path: str | Path, status: str, message: str, lines=(), types_out=()) -> None:
    if status != 'ready':
        lines = ()
        types_out = ()

    header = f'PEELF_DECOMPILE 3\n{status} {quoted(message)}\n'
    encoded_lines: list[str] = []
    used_bytes = len(header.encode('utf-8')) + 32

    for item in lines:
        if len(item) == 2 and isinstance(item[0], (list, tuple)):
            raw_ranges, text = item
        else:
            addr, text = item
            raw_ranges = [(int(addr), 1)] if addr is not None else []

        valid_ranges: list[tuple[int, int]] = []
        for r_addr, r_size in raw_ranges[:MAX_RANGES_PER_LINE]:
            ia = int(r_addr)
            isz = int(r_size)
            if ia < 0 or isz < 1:
                continue
            if isz > MAX_RANGE_SIZE:
                isz = MAX_RANGE_SIZE
            if ia > UINT64_MAX - isz:
                continue
            valid_ranges.append((ia, isz))

        range_tokens = ' '.join(f'{ra} {rs}' for ra, rs in valid_ranges)
        prefix = f'{len(valid_ranges)} {range_tokens} ' if valid_ranges else '0 '
        line_str = f'{prefix}{quoted(text)}\n'
        line_bytes = len(line_str.encode('utf-8'))
        if used_bytes + line_bytes > MAX_OUTPUT_BYTES:
            break
        encoded_lines.append(line_str)
        used_bytes += line_bytes

    if status == 'ready' and not encoded_lines:
        header = f'PEELF_DECOMPILE 3\nfailed {quoted("Empty decompiler output.")}\n'
        types_out = ()

    encoded_types: list[str] = []
    for t_name, t_size, is_union, members in list(types_out)[:MAX_TYPES]:
        clean_name = str(t_name).strip()
        tsize = int(t_size)
        if not clean_name or tsize < 0 or tsize > MAX_TYPE_SIZE:
            continue
        valid_members: list[str] = []
        for m_off, m_sz, m_name, m_type in list(members)[:MAX_TYPE_MEMBERS]:
            moff = int(m_off)
            msz = int(m_sz)
            if moff < 0 or moff > tsize:
                continue
            if msz < 0:
                continue
            if msz > tsize - moff:
                msz = tsize - moff
            valid_members.append(f'{moff} {msz} {quoted(m_name)} {quoted(m_type)}\n')

        block = (
            f'{quoted(clean_name)} {tsize} {1 if is_union else 0} {len(valid_members)}\n'
            + ''.join(valid_members)
        )
        block_bytes = len(block.encode('utf-8'))
        if used_bytes + block_bytes > MAX_OUTPUT_BYTES:
            break
        encoded_types.append(block)
        used_bytes += block_bytes

    with Path(path).open('w', encoding='utf-8', newline='\n') as output:
        output.write(header)
        output.write(f'{len(encoded_lines)}\n')
        for entry in encoded_lines:
            output.write(entry)
        output.write(f'{len(encoded_types)}\n')
        for tblock in encoded_types:
            output.write(tblock)


def decode_hex_field(token: str) -> str:
    if not token or token == '-':
        return ''
    try:
        return bytes.fromhex(token).decode('utf-8', errors='replace')
    except ValueError:
        return ''


def parse_peelf_symbols(symbols_path: str | Path | None):
    if not symbols_path:
        return [], []
    p = Path(symbols_path)
    try:
        if not p.is_file() or p.stat().st_size > 16 * 1024 * 1024:
            return [], []
        tokens = p.read_text(encoding='utf-8', errors='replace').split()
    except OSError:
        return [], []

    if len(tokens) < 5 or tokens[0] != 'PEELF_SYMBOLS' or tokens[1] != '1':
        return [], []

    idx = 4  # skip magic, version, req_addr, req_func_size
    try:
        sym_count = int(tokens[idx])
        idx += 1
        parsed_syms = []
        for _ in range(min(sym_count, 200000)):
            s_addr = int(tokens[idx])
            s_size = int(tokens[idx + 1])
            s_func = tokens[idx + 2] != '0'
            s_name = decode_hex_field(tokens[idx + 3])
            idx += 4
            if s_name:
                parsed_syms.append((s_addr, s_size, s_func, s_name))

        parsed_types = []
        if idx < len(tokens):
            type_count = int(tokens[idx])
            idx += 1
            for _ in range(min(type_count, MAX_TYPES)):
                t_name = decode_hex_field(tokens[idx])
                t_size = int(tokens[idx + 1])
                t_union = tokens[idx + 2] != '0'
                m_count = int(tokens[idx + 3])
                idx += 4
                members = []
                for _ in range(min(m_count, MAX_TYPE_MEMBERS)):
                    m_off = int(tokens[idx])
                    m_sz = int(tokens[idx + 1])
                    m_name = decode_hex_field(tokens[idx + 2])
                    m_type = decode_hex_field(tokens[idx + 3])
                    idx += 4
                    members.append((m_off, m_sz, m_name, m_type))
                if t_name:
                    parsed_types.append((t_name, t_size, t_union, members))
        return parsed_syms, parsed_types
    except (IndexError, ValueError):
        return [], []


def apply_symbols_to_view(bn, view, symbols) -> None:
    if not symbols:
        return
    mutated = False
    sym_cls = getattr(bn, 'Symbol', None)
    sym_type_cls = getattr(bn, 'SymbolType', None)
    define_sym = getattr(view, 'define_user_symbol', None)
    get_fn_at = getattr(view, 'get_function_at', None)
    create_fn = getattr(view, 'create_user_function', None)

    for s_addr, _s_size, is_func, s_name in symbols:
        try:
            fn = get_fn_at(s_addr) if callable(get_fn_at) else None
            if fn is None and is_func and callable(create_fn):
                create_fn(s_addr)
                fn = get_fn_at(s_addr) if callable(get_fn_at) else None
            if fn is not None:
                fn.name = s_name
                mutated = True
            elif callable(sym_cls) and sym_type_cls is not None and callable(define_sym):
                kind = (
                    getattr(sym_type_cls, 'FunctionSymbol', None)
                    if is_func
                    else getattr(sym_type_cls, 'DataSymbol', None)
                )
                if kind is not None:
                    define_sym(sym_cls(kind, s_addr, s_name))
                    mutated = True
        except Exception:
            continue

    if mutated and callable(getattr(view, 'update_analysis_and_wait', None)):
        try:
            view.update_analysis_and_wait()
        except Exception:
            pass


def default_instruction_size(arch_hint: str | None) -> int:
    if arch_hint in ('arm64', 'arm32', 'mips32', 'mips64', 'ppc32', 'ppc64', 'riscv32', 'riscv64'):
        return 4
    return 1


def extract_line_ranges(view, function, line, fallback_insn_size: int) -> list[tuple[int, int]]:
    explicit = getattr(line, 'ranges', None)
    if explicit is not None:
        out: list[tuple[int, int]] = []
        for r in explicit:
            if isinstance(r, (tuple, list)) and len(r) == 2:
                out.append((int(r[0]), max(1, int(r[1]))))
            elif hasattr(r, 'address') and hasattr(r, 'size'):
                out.append((int(r.address), max(1, int(r.size))))
        return out

    candidate_addrs: list[int] = []
    il_ins = getattr(line, 'il_instruction', None)
    if il_ins is not None:
        llils = getattr(il_ins, 'llils', None)
        if llils:
            for ll in llils:
                ll_addr = getattr(ll, 'address', None)
                if ll_addr is not None:
                    ia = int(ll_addr)
                    if ia not in candidate_addrs:
                        candidate_addrs.append(ia)
        if not candidate_addrs:
            il_addr = getattr(il_ins, 'address', None)
            if il_addr is not None:
                candidate_addrs.append(int(il_addr))

    if not candidate_addrs:
        line_addr = getattr(line, 'address', None)
        if line_addr is not None:
            candidate_addrs.append(int(line_addr))

    if not candidate_addrs:
        return []

    candidate_addrs.sort()
    get_len = getattr(view, 'get_instruction_length', None)
    fn_arch = getattr(function, 'arch', None)

    raw_spans: list[tuple[int, int]] = []
    for addr in candidate_addrs[:MAX_RANGES_PER_LINE]:
        if addr < 0 or addr > UINT64_MAX - 1:
            continue
        insn_len = 0
        if callable(get_len):
            try:
                insn_len = int(get_len(addr, fn_arch) if fn_arch is not None else get_len(addr))
            except TypeError:
                try:
                    insn_len = int(get_len(addr))
                except Exception:
                    insn_len = 0
            except Exception:
                insn_len = 0
        if insn_len <= 0:
            insn_len = fallback_insn_size
        insn_len = min(MAX_RANGE_SIZE, max(1, insn_len))
        if addr <= UINT64_MAX - insn_len:
            raw_spans.append((addr, insn_len))

    merged: list[tuple[int, int]] = []
    for addr, size in raw_spans:
        if not merged:
            merged.append((addr, size))
            continue
        prev_addr, prev_size = merged[-1]
        prev_end = prev_addr + prev_size
        cur_end = addr + size
        if addr <= prev_end and cur_end - prev_addr <= MAX_RANGE_SIZE:
            merged[-1] = (prev_addr, max(prev_end, cur_end) - prev_addr)
        else:
            merged.append((addr, size))
    return merged


def extract_view_types(view, seeded_types=()) -> list[tuple[str, int, bool, list[tuple[int, int, str, str]]]]:
    exported: list[tuple[str, int, bool, list[tuple[int, int, str, str]]]] = []
    seen_names: set[str] = set()

    view_types = getattr(view, 'types', None)
    items = []
    if view_types is not None:
        if callable(getattr(view_types, 'items', None)):
            items = list(view_types.items())
        else:
            try:
                items = list(view_types)
            except TypeError:
                items = []

    for raw_name, type_obj in items[:MAX_TYPES]:
        t_name = str(raw_name).strip()
        if not t_name or t_name in seen_names or type_obj is None:
            continue

        struct_obj = getattr(type_obj, 'structure', None)
        if struct_obj is None:
            tclass = str(getattr(type_obj, 'type_class', '')).lower()
            if hasattr(type_obj, 'members') and ('structure' in tclass or not tclass):
                struct_obj = type_obj
        if struct_obj is None:
            continue

        try:
            width = int(getattr(struct_obj, 'width', getattr(type_obj, 'width', 0)) or 0)
        except (TypeError, ValueError):
            continue
        if width < 0 or width > MAX_TYPE_SIZE:
            continue

        variant_text = str(
            getattr(struct_obj, 'type', getattr(struct_obj, 'variant', ''))
        ).lower()
        is_union = bool(getattr(struct_obj, 'is_union', False) or 'union' in variant_text)

        raw_members = getattr(struct_obj, 'members', None) or ()
        members: list[tuple[int, int, str, str]] = []
        for m in list(raw_members)[:MAX_TYPE_MEMBERS]:
            try:
                m_off = int(getattr(m, 'offset', 0))
            except (TypeError, ValueError):
                continue
            if m_off < 0 or m_off > width:
                continue
            m_type_obj = getattr(m, 'type', None)
            try:
                m_sz = int(getattr(m, 'width', getattr(m_type_obj, 'width', 0)) or 0)
            except (TypeError, ValueError):
                m_sz = 0
            if m_sz < 0:
                continue
            if m_sz > width - m_off:
                m_sz = width - m_off
            m_name = str(getattr(m, 'name', '') or '')
            m_type_str = str(m_type_obj) if m_type_obj is not None else ''
            members.append((m_off, m_sz, m_name, m_type_str))

        seen_names.add(t_name)
        exported.append((t_name, width, is_union, members))

    for t_name, t_size, t_union, members in seeded_types:
        if t_name not in seen_names and len(exported) < MAX_TYPES:
            seen_names.add(t_name)
            exported.append((t_name, t_size, t_union, members))

    return exported


def check_runtime_capabilities(bn, arch_hint: str | None) -> str | None:
    product = ''
    if callable(getattr(bn, 'core_product', None)):
        try:
            product = str(bn.core_product() or '')
        except Exception:
            product = ''
    edition = classify_edition(product)
    if edition == 'Free':
        if arch_hint and arch_hint not in ('x86', 'x86_64', 'unknown'):
            return (
                f"Architecture '{arch_hint}' is not supported on Binary Ninja Free "
                '(x86/x64-only interactive edition). Upgrade to Personal, Commercial, or Ultimate.'
            )
        return (
            'Binary Ninja Free does not support headless Python batch decompilation '
            '(requires Personal, Commercial, Ultimate, or Headless license).'
        )

    if arch_hint and arch_hint in ARCH_ALIASES:
        registered = {name.lower() for name in enumerate_bn_architectures(bn)}
        if registered and not (registered & ARCH_ALIASES[arch_hint]):
            return (
                f"Architecture '{arch_hint}' is not supported by the active Binary Ninja installation."
            )
    return None


def main(
    source: str | Path,
    destination: str | Path,
    address: str | int,
    *,
    bn_home: str | Path | None = None,
    arch: str | None = None,
    symbols: str | Path | None = None,
) -> None:
    configure_bn_home(bn_home)
    try:
        import binaryninja as bn
        if bn is None:
            raise ImportError('binaryninja module is None')
    except ImportError as exc:
        write_result(destination, 'unavailable', f'Binary Ninja Python API is not installed in this interpreter ({exc}).')
        return
    except Exception as exc:
        if is_license_or_free_error(exc):
            write_result(
                destination,
                'unsupported',
                f'Binary Ninja headless Python API unavailable ({exc}). '
                'Headless batch decompilation requires Personal, Commercial, Ultimate, or Headless.',
            )
        else:
            write_result(destination, 'unavailable', f'Failed to initialize Binary Ninja Python API: {exc}')
        return

    cap_err = check_runtime_capabilities(bn, arch)
    if cap_err is not None:
        write_result(destination, 'unsupported', cap_err)
        return

    parsed_syms, seeded_types = parse_peelf_symbols(symbols)

    try:
        target_addr = int(address)
        loaded = bn.load(str(source) if isinstance(source, Path) else source)
        if loaded is None:
            write_result(destination, 'unsupported', 'Backend cannot load this binary.')
            return

        ctx = loaded if hasattr(loaded, '__enter__') else nullcontext(loaded)
        with ctx as view:
            if getattr(view, 'arch', None) is None:
                write_result(destination, 'unsupported', 'Backend cannot analyze this binary architecture.')
                return

            apply_symbols_to_view(bn, view, parsed_syms)

            functions = view.get_functions_containing(target_addr)
            if not functions and callable(getattr(view, 'get_function_at', None)):
                direct = view.get_function_at(target_addr)
                if direct is not None:
                    functions = [direct]
            if not functions:
                write_result(destination, 'no_function', 'No analyzed function contains the selected address.')
                return

            function = functions[0]
            if getattr(function, 'hlil', None) is None:
                write_result(destination, 'unsupported', 'HLIL is unavailable for this function or backend edition.')
                return

            root = getattr(function.hlil, 'root', None)
            raw_lines = list(getattr(root, 'lines', root or ()))
            if len(raw_lines) > MAX_LINES:
                write_result(destination, 'failed', 'Decompiled function exceeds line limit.')
                return

            fallback_sz = default_instruction_size(arch)
            mapped_lines = [
                (extract_line_ranges(view, function, line, fallback_sz), str(line))
                for line in raw_lines
            ]
            if not mapped_lines:
                write_result(destination, 'no_function', 'HLIL produced zero lines for the selected function.')
                return

            exported_types = extract_view_types(view, seeded_types)
            write_result(
                destination,
                'ready',
                'Decompiled with Binary Ninja HLIL (PEELF_DECOMPILE 3).',
                mapped_lines,
                exported_types,
            )
    except Exception as error:
        if is_license_or_free_error(error):
            write_result(
                destination,
                'unsupported',
                f'Binary Ninja license/edition limitation: {error}',
            )
        else:
            write_result(destination, 'failed', f'Binary Ninja analysis failed: {error}')


def cli(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    if '--probe' in args_list:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument('--probe', required=True)
        parser.add_argument('--bn-home', default=None)
        parsed, _ = parser.parse_known_args(args_list)
        run_probe(parsed.probe, bn_home=parsed.bn_home)
        return 0

    parser = argparse.ArgumentParser(description='exe_viewer Binary Ninja HLIL bridge')
    parser.add_argument('source')
    parser.add_argument('destination')
    parser.add_argument('address')
    parser.add_argument('--bn-home', default=None)
    parser.add_argument('--arch', default=None)
    parser.add_argument('--symbols', default=None)
    parsed = parser.parse_args(args_list)
    main(
        parsed.source,
        parsed.destination,
        parsed.address,
        bn_home=parsed.bn_home,
        arch=parsed.arch,
        symbols=parsed.symbols,
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(cli())

