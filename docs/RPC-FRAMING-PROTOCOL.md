# S7 HE RPC framing: static findings

Target: the original Ubisoft History Edition executable, SHA-256 `4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f`. Addresses are x86 virtual addresses at preferred base 0x400000. The framing findings below were derived statically. The opt-in local Login probe now implements bounded reassembly, known Login/Register argument validation and encrypted responses; see [the experiment and live evidence](LOCAL-LOGIN-PROBE.md). Other RPC services remain unimplemented.

## Outer message and request header

The LoginWithToken builder `E9663E` creates a Message via `E679F0`. Initialization reserves four bytes at `E680C9–E680CD` and positions the reader after them at `E67A89–E67A8D`. Before sending, `E92F38–E92F49` obtains the completed buffer through `E67F60`: it temporarily truncates the buffer, writes a u32LE equal to the previous content length minus four (`E67F7B–E67F8B`), restores the extent, and returns the whole buffer. Thus byte 0 is a message length excluding its own four-byte prefix. It is not a per-fragment or encrypted-body length.

The request then contains:

| Order | Field | Evidence |
|---|---|---|
| 1 | Protocol string | `E9664D–E96667 → E9B290 → E99C50` |
| 2 | u8 request flag, 1 for this request | `E99C50`; reciprocal reader `E9A110` |
| 3 | u32LE call ID | `E9667B–E96682 → E9A260`, context+0x40 |
| 4 | Method string | `E96695–E966AE → E99C30` |
| 5 | Further object and arguments, not derived here | `EB0D00`, `EAFCB0`, `E996C0`, `EAFC50` |

Both header strings use u16LE length including terminal NUL, followed by that many bytes. `E67470 → E674E0` checks the non-NUL string length against a maximum of 254 for these calls. `E67552–E67574` writes length+1 and copies the bytes including NUL. They are not numeric protocol/method IDs from older Quazal variants. `E97100` returns the literal protocol `LoginProtocol`; this request's method is `LoginProtocol::LoginWithToken_V1`.

A future classifier should validate the complete outer length before reading the header, compare bytes against a fixed allowlist, and stop before arguments. Call IDs, arbitrary strings and bodies need not appear in diagnostics. A recognized request would not establish authentication or determine its response.

## Fragmentation and ordering

The reliable sender `EBA7B0` copies consecutive slices of the entire Message buffer. Its nonfinal part numbers start at 1, increment through 255 and wrap to 1; the final part is 0 (`EBA8D1–EBA8EA`). An unfragmented message is one packet with part 0. Part number is neither fragment count nor DATA sequence. LoginWithToken's send path requests reliable delivery.

Each fragment is independently decrypted, decompressed and checked against its own encrypted sequence suffix before reliable ordering (`EBBD47–EBBD7C`); see [DATA transformations](DATA-CRYPTO-PROTOCOL.md). Concatenating ciphertext and decrypting once would be incorrect.

The reliable receive queue `EC1C80` orders by modular u16 sequence, ignores older/duplicate entries, and does not dispatch a packet across a missing sequence. `EC1BA0` drains the expected sequence. Initial expected sequence is 1, and reliable CONNECT/control packets also use this queue; therefore DATA ordering must not be initialized independently by guessing its first number.

For reliable DATA, `EBC61A → EBA5C0` accumulates the transformed payload bytes. It expects successive nonzero part numbers, clears assembly on an unexpected part, and finishes on part 0. `E6C1C0` appends buffers with no inserted framing. The caller delivers the assembled buffer, resets expected part to 1 and clears it at `EBC624–EBC643`. Unreliable DATA follows a direct delivery path and must not blindly use those assembly rules.

The resulting order is packet validation, per-packet transformation, reliable deduplication/ordering, plaintext concatenation, outer-length validation, then RPC header parsing at offset 4. A final part is not an independent message when earlier fragments are missing.

## Remaining limits

The complete incoming event-handler-to-RPC linkage, all message input validation, multi-message aggregation, native size/window limits, recovery rules and login semantics remain unresolved. These findings do not establish the contents of the DATA packets observed in the live test. No real payloads or disassembly dumps are distributed. A future implementation needs bounded, transient assembly storage and synthetic out-of-order, missing-part, duplicate and wraparound tests before live use.
