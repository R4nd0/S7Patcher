"""Read and append replacements to S7 production BBA archives.

Format/crypto adapted from Eisenmonoxid/S7Packer (MIT, copyright 2025).
See LICENSE.S7Packer.txt. Existing entry order, names and filename hash tables
are retained; this module never opens an input file for writing.
"""
from dataclasses import dataclass
import gzip
import struct
import zlib

MASK = 0xFFFFFFFF
MIB = 1048576
HEAD_KEYS = (623092400, 3578011951, 428883204, 211416760)
FILE_KEYS = (892421091, 3702197895, 3064602941, 189782668)
XOR = (68040748, 166934560, 1719695735, 4247314248)


def crc32(data):
    return zlib.crc32(data) & MASK


def _mix(y, z, total, key):
    return (((y >> 5 ^ z << 2) + (y << 4 ^ z >> 3))
            ^ ((total ^ z) + (key ^ y))) & MASK


def crypt(data, keys, delta, rounds, encrypt=False):
    if len(data) < 8 or len(data) % 4:
        raise ValueError("Invalid BBA encrypted block size")
    words = list(struct.unpack("<" + "I" * (len(data) // 4), data))
    total = 0 if encrypt else (rounds * delta) & MASK
    for _ in range(rounds):
        if encrypt:
            total = (total + delta) & MASK
            e = (total >> 2) & 3
            y = words[-1]
            for p in range(len(words) - 1):
                z = words[p + 1]
                words[p] = (words[p] + _mix(y, z, total, keys[(p & 3) ^ e])) & MASK
                y = words[p]
            words[-1] = (words[-1] + _mix(y, words[0], total, keys[((len(words) - 1) & 3) ^ e])) & MASK
        else:
            e = (total >> 2) & 3
            z = words[0]
            for p in range(len(words) - 1, 0, -1):
                y = words[p - 1]
                words[p] = (words[p] - _mix(y, z, total, keys[(p & 3) ^ e])) & MASK
                z = words[p]
            words[0] = (words[0] - _mix(words[-1], z, total, keys[e])) & MASK
            total = (total - delta) & MASK
    return struct.pack("<" + "I" * len(words), *words)


def _gzip_xor(payload, name_length, encrypt=False):
    result = bytearray(payload)
    for offset in range(0, len(result), MIB):
        if len(result) - offset < 16:
            raise ValueError("BBA compressed chunk is too short")
        words = list(struct.unpack_from("<4I", result, offset))
        if encrypt:
            words[0] ^= words[3] ^ name_length ^ XOR[0]
            words[1] ^= words[0] ^ name_length ^ XOR[1]
            words[2] ^= words[1] ^ name_length ^ XOR[2]
            words[3] ^= words[2] ^ name_length ^ XOR[3]
        else:
            words[3] ^= words[2] ^ name_length ^ XOR[3]
            words[2] ^= words[1] ^ name_length ^ XOR[2]
            words[1] ^= words[0] ^ name_length ^ XOR[1]
            words[0] ^= words[3] ^ name_length ^ XOR[0]
        struct.pack_into("<4I", result, offset, *words)
    return bytes(result)


@dataclass(frozen=True)
class Entry:
    name: str
    directory_offset: int
    values: tuple


class Archive:
    def __init__(self, raw):
        self.raw = bytes(raw)
        if len(raw) < 32 or raw[:4] != b"BAF\x06":
            raise ValueError("Not a supported production BBA v6 archive")
        self.header_size = struct.unpack_from("<I", raw, 8)[0]
        if self.header_size not in (16, 64) or 16 + self.header_size > len(raw):
            raise ValueError("Unsupported BBA header size")
        self.header = crypt(raw[16:16 + self.header_size], HEAD_KEYS, 1231853475, 7)
        offset, high, size, checksum = struct.unpack_from("<4I", self.header)
        if high or offset < 16 + self.header_size or offset + size > len(raw):
            raise ValueError("Invalid BBA directory range")
        encoded = raw[offset:offset + size]
        if crc32(encoded) != checksum:
            raise ValueError("BBA encrypted directory CRC32 mismatch")
        self.directory = crypt(encoded, FILE_KEYS, 1532281822, 8)
        if len(self.directory) < 276:
            raise ValueError("BBA directory is truncated")
        _, entries_offset, self.hash_table_offset = struct.unpack_from("<3I", self.directory)
        if entries_offset != 272 or not 276 <= self.hash_table_offset <= len(self.directory) - 4:
            raise ValueError("Unsupported BBA directory layout")
        count = struct.unpack_from("<I", self.directory, entries_offset)[0]
        if not 0 < count <= 100000:
            raise ValueError("Invalid BBA entry count")
        position = entries_offset + 4
        self.entries = {}
        for _ in range(count):
            if position + 64 > self.hash_table_offset:
                raise ValueError("Truncated BBA entry")
            values = struct.unpack_from("<16I", self.directory, position)
            name_length = values[12]
            padded = ((name_length + 3) & ~3) + (4 if name_length % 4 == 0 else 0)
            if not 0 < name_length < 10000 or position + 64 + padded > self.hash_table_offset:
                raise ValueError("Invalid BBA entry name")
            name = self.directory[position + 64:position + 64 + name_length].rstrip(b"\0").decode("ascii").replace("\\", "/")
            if name in self.entries:
                raise ValueError("Duplicate BBA entry: " + name)
            self.entries[name] = Entry(name, position, values)
            position += 64 + padded
        if position != self.hash_table_offset:
            raise ValueError("Unexpected bytes between BBA entries and hash table")
        hash_count = struct.unpack_from("<I", self.directory, self.hash_table_offset)[0]
        if self.hash_table_offset + 4 + hash_count * 8 != len(self.directory):
            raise ValueError("Invalid BBA filename hash table size")

    def read(self, name):
        entry = self.entries[name]
        v = entry.values
        if v[4] == 256:
            raise ValueError("Cannot read a BBA directory as a file")
        if v[6] < 16 + self.header_size or v[6] + v[8] > len(self.raw):
            raise ValueError("Invalid BBA payload range: " + name)
        payload = self.raw[v[6]:v[6] + v[8]]
        # The pristine Ubisoft HE Interface.bba has stale stored compressed
        # checksums for 206 of its 284 files. The whole input fingerprint is
        # pinned by prepare.py; directory CRC and decompressed CRC/size remain
        # mandatory. Newly written payloads receive their actual encoded CRC.
        if v[4] == 17:
            result = gzip.decompress(_gzip_xor(payload, v[12]))
        elif v[4] == 0:
            result = payload
        elif v[4] == 2:
            if not 0 < v[10] <= MIB:
                raise ValueError("Unsupported BBA TEA block size")
            result = b"".join(crypt(payload[p:p + v[10]] + b"\0" * (-len(payload[p:p + v[10]]) % 4),
                                    tuple(key ^ v[12] for key in FILE_KEYS), 1532281822, 8)[:len(payload[p:p + v[10]])]
                              for p in range(0, len(payload), v[10]))
        else:
            raise ValueError("Unsupported BBA file type: " + str(v[4]))
        if len(result) != v[2] or crc32(result) != v[3]:
            raise ValueError("BBA decompressed size/CRC32 mismatch: " + name)
        return result

    def replace(self, replacements):
        """Return new bytes; existing payloads/tables remain in place, unused.

        Only existing entries can be replaced. This intentionally does not add
        names or rebuild the game's filename lookup tables.
        """
        if not replacements:
            raise ValueError("No BBA replacements were supplied")
        result = bytearray(self.raw)
        directory = bytearray(self.directory)
        for name, data in replacements.items():
            entry = self.entries[name]
            self.read(name)  # Validate original content before creating a delta.
            v = list(entry.values)
            if v[4] not in (0, 17):
                raise ValueError("Replacing this BBA file type is not supported: " + name)
            encoded = _gzip_xor(gzip.compress(data, compresslevel=9, mtime=0), v[12], True) if v[4] == 17 else data
            v[2], v[3], v[6], v[8], v[9] = len(data), crc32(data), len(result), len(encoded), crc32(encoded)
            if any(value > MASK for value in v):
                raise ValueError("Replacement exceeds the BBA 32-bit limit")
            struct.pack_into("<16I", directory, entry.directory_offset, *v)
            result.extend(encoded)
        encoded_directory = crypt(directory, FILE_KEYS, 1532281822, 8, True)
        header = bytearray(self.header)
        struct.pack_into("<4I", header, 0, len(result), 0, len(encoded_directory), crc32(encoded_directory))
        result[16:16 + self.header_size] = crypt(header, HEAD_KEYS, 1231853475, 7, True)
        result.extend(encoded_directory)
        if directory[self.hash_table_offset:] != self.directory[self.hash_table_offset:]:
            raise ValueError("BBA hash table unexpectedly changed")
        verified = Archive(result)
        for name, data in replacements.items():
            if verified.read(name) != data:
                raise ValueError("BBA replacement failed round-trip validation: " + name)
        return bytes(result)
