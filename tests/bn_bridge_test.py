"""Exercise bridge behavior without requiring a licensed backend."""
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
    def run_bridge(self, backend):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'output.txt'
            with patch.dict(sys.modules, {'binaryninja': backend}):
                bridge.main('fixture.bin', destination, '4096')
            return destination.read_text(encoding='utf-8')

    def test_missing_api(self):
        self.assertIn('\nunavailable ', self.run_bridge(None))

    def test_unsupported_input(self):
        backend = types.SimpleNamespace(load=lambda _: None)
        self.assertIn('\nunsupported ', self.run_bridge(backend))

    def test_mapped_output_and_escaping(self):
        class Line:
            address = 4096
            def __str__(self):
                return 'return "hello";'

        class View:
            arch = 'x86_64'
            def __enter__(self):
                return self
            def __exit__(self, *_):
                pass
            def get_functions_containing(self, address):
                assert address == 4096
                return [types.SimpleNamespace(hlil=types.SimpleNamespace(
                    root=types.SimpleNamespace(lines=[Line()]))) ]

        result = self.run_bridge(types.SimpleNamespace(load=lambda _: View()))
        self.assertIn('\nready ', result)
        self.assertIn('4096 "return \\"hello\\";"', result)


if __name__ == '__main__':
    unittest.main()
