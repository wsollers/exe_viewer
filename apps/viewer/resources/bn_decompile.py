"""Optional Binary Ninja bridge. Uses a local installation; never executes the input binary.

API reference: https://docs.binary.ninja/dev/cookbook.html#il-decompilation
The GUI runs this process with a deadline and an isolated effective-byte snapshot.
"""
import sys
from pathlib import Path


def quoted(value):
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"').replace('\r', ' ').replace('\n', ' ') + '"'


def write_result(path, status, message, lines=()):
    with Path(path).open('w', encoding='utf-8', newline='\n') as output:
        output.write(f'PEELF_DECOMPILE 1\n{status} {quoted(message)}\n{len(lines)}\n')
        for address, text in lines:
            output.write(f'{address} {quoted(text)}\n')


def main(source, destination, address):
    try:
        import binaryninja as bn
    except ImportError:
        write_result(destination, 'unavailable', 'Binary Ninja Python API is not installed in this interpreter.')
        return
    try:
        loaded = bn.load(source)
        if loaded is None:
            write_result(destination, 'unsupported', 'Backend cannot load this binary.')
            return
        with loaded as view:
            if view.arch is None:
                write_result(destination, 'unsupported', 'Backend cannot analyze this binary architecture.')
                return
            functions = view.get_functions_containing(int(address))
            if not functions:
                write_result(destination, 'no_function', 'No analyzed function contains the selected address.')
                return
            function = functions[0]
            if function.hlil is None:
                write_result(destination, 'unsupported', 'HLIL is unavailable for this function or backend edition.')
                return
            lines = [(line.address, str(line)) for line in function.hlil.root.lines]
            if len(lines) > 100000:
                write_result(destination, 'failed', 'Decompiled function exceeds line limit.')
                return
            write_result(destination, 'ready', 'HLIL address mappings are approximate.', lines)
    except Exception as error:
        write_result(destination, 'failed', f'Binary Ninja analysis failed: {error}')


if __name__ == '__main__':
    main(*sys.argv[1:4])
