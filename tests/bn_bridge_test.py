"""Exercise Binary Ninja bridge v3 output, capability probing, symbols, and edition gating."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'bridge', Path(__file__).parents[1] / 'apps/viewer/resources/bn_decompile.py')
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class BridgeTest(unittest.TestCase):
    def run_bridge(self, backend, *, arch=None, symbols=None, bn_home=None):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'output.txt'
            with patch.dict(sys.modules, {'binaryninja': backend}):
                bridge.main(
                    'fixture.bin',
                    destination,
                    '4096',
                    bn_home=bn_home,
                    arch=arch,
                    symbols=symbols,
                )
            return destination.read_text(encoding='utf-8')

    def test_missing_api(self):
        out = self.run_bridge(None)
        self.assertTrue(out.startswith('PEELF_DECOMPILE 3\n'))
        self.assertIn('\nunavailable ', out)

    def test_unsupported_input(self):
        backend = types.SimpleNamespace(load=lambda _: None)
        out = self.run_bridge(backend)
        self.assertTrue(out.startswith('PEELF_DECOMPILE 3\n'))
        self.assertIn('\nunsupported ', out)

    def test_mapped_output_v3_ranges_escaping_and_types(self):
        class Line:
            address = 4096
            il_instruction = types.SimpleNamespace(
                llils=[
                    types.SimpleNamespace(address=4096),
                    types.SimpleNamespace(address=4100),
                    types.SimpleNamespace(address=4120),
                ]
            )

            def __str__(self):
                return 'return "hello";'

        pkt_members = [
            types.SimpleNamespace(offset=0, width=4, name='magic', type='uint32_t'),
            types.SimpleNamespace(offset=4, width=4, name='length', type='uint32_t'),
            # Out-of-bounds member width should be safely clamped, and negative offset skipped.
            types.SimpleNamespace(offset=6, width=99, name='tail', type='uint16_t'),
            types.SimpleNamespace(offset=-4, width=4, name='bad', type='int32_t'),
        ]
        pkt_struct = types.SimpleNamespace(
            type_class='StructureTypeClass',
            width=8,
            type='StructStructureType',
            members=pkt_members,
        )
        union_type = types.SimpleNamespace(
            type_class='StructureTypeClass',
            width=8,
            type='UnionStructureType',
            members=[
                types.SimpleNamespace(offset=0, width=8, name='raw_u64', type='uint64_t'),
                types.SimpleNamespace(offset=0, width=4, name='low_u32', type='uint32_t'),
            ],
        )

        class View:
            arch = 'x86_64'
            types = {'PacketHeader': pkt_struct, 'ValueUnion': union_type}

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def get_instruction_length(self, addr):
                return 4

            def get_functions_containing(self, address):
                assert address == 4096
                return [
                    types.SimpleNamespace(
                        arch='x86_64',
                        hlil=types.SimpleNamespace(
                            root=types.SimpleNamespace(lines=[Line()])
                        ),
                    )
                ]

        result = self.run_bridge(types.SimpleNamespace(load=lambda _: View()), arch='x86_64')
        self.assertTrue(result.startswith('PEELF_DECOMPILE 3\nready '))
        # Contiguous 4096..4104 merged into (4096, 8), plus disjoint (4120, 4) -> 2 ranges!
        self.assertIn('\n2 4096 8 4120 4 "return \\"hello\\";"\n', result)
        self.assertIn('"PacketHeader" 8 0 3\n0 4 "magic" "uint32_t"\n4 4 "length" "uint32_t"\n6 2 "tail" "uint16_t"\n', result)
        self.assertIn('"ValueUnion" 8 1 2\n', result)

    def test_free_edition_diagnostics(self):
        free_backend = types.SimpleNamespace(
            core_product=lambda: 'Binary Ninja Free',
            core_version=lambda: '4.2.6455',
            Architecture=[types.SimpleNamespace(name='x86'), types.SimpleNamespace(name='x86_64')],
            load=lambda _: None,
        )
        arm64_out = self.run_bridge(free_backend, arch='arm64')
        self.assertIn('\nunsupported ', arm64_out)
        self.assertIn('arm64', arm64_out)
        self.assertIn('Binary Ninja Free', arm64_out)

        x64_out = self.run_bridge(free_backend, arch='x86_64')
        self.assertIn('\nunsupported ', x64_out)
        self.assertIn('headless', x64_out.lower())

    def test_probe_and_symbols_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            py_pkg = tmp / 'bn_root' / 'python' / 'binaryninja'
            py_pkg.mkdir(parents=True)
            (py_pkg / '__init__.py').write_text(
                'class _Arch:\n'
                '    def __init__(self, name): self.name = name\n'
                'Architecture = [_Arch("x86_64"), _Arch("aarch64")]\n'
                'def core_version(): return "4.2.9999"\n'
                'def core_product(): return "Binary Ninja Commercial"\n'
                'def load(path): return None\n',
                encoding='utf-8',
            )
            probe_out = tmp / 'probe.txt'
            saved_mod = sys.modules.pop('binaryninja', None)
            try:
                rc = bridge.cli(['--probe', str(probe_out), '--bn-home', str(tmp / 'bn_root')])
                self.assertEqual(rc, 0)
                probe_text = probe_out.read_text(encoding='utf-8')
                self.assertTrue(probe_text.startswith('PEELF_BN_PROBE 1\n1 1 "Commercial" "4.2.9999"'))
                self.assertIn('"x86_64"', probe_text)
                self.assertIn('"aarch64"', probe_text)
            finally:
                sys.modules.pop('binaryninja', None)
                if saved_mod is not None:
                    sys.modules['binaryninja'] = saved_mod

            # Verify PEELF_SYMBOLS 1 rename application.
            sym_file = tmp / 'symbols.txt'
            sym_file.write_text(
                'PEELF_SYMBOLS 1\n'
                '4096 32\n'
                '1\n'
                f'4096 32 1 {"renamed_entry".encode().hex()}\n'
                '0\n',
                encoding='utf-8',
            )
            fn_obj = types.SimpleNamespace(
                name='sub_1000',
                arch='x86_64',
                hlil=types.SimpleNamespace(
                    root=types.SimpleNamespace(
                        lines=[types.SimpleNamespace(address=4096, __str__=lambda self: 'return 1;')]
                    )
                ),
            )
            view_obj = types.SimpleNamespace(
                arch='x86_64',
                types={},
                get_function_at=lambda addr: fn_obj if addr == 4096 else None,
                get_functions_containing=lambda addr: [fn_obj] if addr == 4096 else [],
            )
            out = self.run_bridge(
                types.SimpleNamespace(load=lambda _: view_obj),
                symbols=sym_file,
            )
            self.assertEqual(fn_obj.name, 'renamed_entry')
            self.assertIn('\nready ', out)


if __name__ == '__main__':
    unittest.main()

