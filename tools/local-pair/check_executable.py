"""Read-only validation against a user-supplied original; writes no game files."""
import argparse
from pathlib import Path
import lab_executable


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('original', type=Path)
    args = parser.parse_args()
    original = args.original.read_bytes()
    allowed = set(range(0xD0EC24, 0xD0EC24 + 16)) | set(range(0xD31594, 0xD31594 + 33))
    checks = 0
    for slot in ('A', 'B'):
        candidate = lab_executable.derive(original, slot)
        assert len(candidate) == len(original)
        assert {i for i, (a, b) in enumerate(zip(original, candidate)) if a != b} <= allowed
        checks += 2
        for value, name in ((candidate, slot), (original[:-1], slot),
                            (bytes([original[0] ^ 1]) + original[1:], slot), (original, 'C')):
            try:
                lab_executable.derive(value, name)
            except ValueError:
                checks += 1
            else:
                raise AssertionError('Executable guard accepted an invalid input')
    assert args.original.read_bytes() == original
    print(f'PASS {checks + 1} real executable derivation/immutability checks')


if __name__ == '__main__':
    main()
