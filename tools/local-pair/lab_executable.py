"""Two fixed development-only data variants; never patch the original in place.

The normal adapter rejects these hashes. Only a LocalPairLab adapter accepts
them. No executable instructions, protocol behavior or timing are changed.
"""
import hashlib

ORIGINAL = '4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f'
HASHES = {
    'A': '722cb6e616851f20fae90b29c8af65df8aa94f353b0739e44c24721cfb574e13',
    'B': '78c7a4b87e2f8dceb95eaaac9ab8cdd559ce482fc800129345e952b711974a8a',
}


def derive(original, slot):
    if slot not in HASHES or hashlib.sha256(original).hexdigest() != ORIGINAL:
        raise ValueError('Wrong executable or laboratory slot')
    result = bytearray(original)
    edits = (
        (0xD0EC24, b'Global\\Settlers7', ('Local\\S7Lab0000' + slot).encode('ascii')),
        (0xD31594, b'\\THE SETTLERS 7 - History Edition',
         ('\\Codex\\2026-10-25\\rec\\work\\S7Lab' + slot).encode('ascii')),
    )
    for offset, before, after in edits:
        if len(before) != len(after) or original[offset:offset + len(before) + 1] != before + b'\0':
            raise ValueError('Laboratory data guard failed')
        result[offset:offset + len(before)] = after
    if len(result) != len(original) or hashlib.sha256(result).hexdigest() != HASHES[slot]:
        raise ValueError('Unexpected laboratory executable')
    return bytes(result)
