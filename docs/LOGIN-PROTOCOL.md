# S7 HE login and registration: static findings

Target: Ubisoft History Edition 1.12.1395, executable SHA-256 `4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f`. These findings describe native parsers and callbacks. They do not establish successful local authentication or prescribe production identity values. No account data or real plaintext was inspected.

## Common response envelope

After the outer u32LE message length described in [RPC framing](RPC-FRAMING-PROTOCOL.md), a response contains the protocol string `LoginProtocol`, response flag u8=0, result discriminator u8, and opaque u32LE call ID. Result 1 is success; result 0 inserts an error-domain string and u16LE error code **before** the call ID. Other result discriminators are invalid. A successful response then contains a method string and its return values. A failed response has no success method/body.

`E97E4B → E99C50` writes response flag 0. `E99BA0 → E99B00` writes result, then call ID, and appends the success body only for a successful result. The client mirrors this at `E92910 → E99E30 → E9A2D0` and dispatches only a found successful call context. Encoding a failure with domain Core/code 0 violates a native assertion.

Protocol and method strings have u16LE length including NUL, maximum 254 non-NUL bytes. The response method ends with a **literal asterisk**. Native concatenation `E96EFF → E59B60` and comparison `E96F0D → E59EC0` establish that this is an exact suffix, not a wildcard.

## Request argument structure

The two methods have different class-version maps. **LoginWithToken_V1 contains one entry, `ClientVersionInfo` with u16 version1; Register_V1 contains an empty map.** Login creates an empty map at `E966C5/E966CC`, then calls `E99720` at `E966E3` before serializing it. `E99720 → EB0E80 → E8B320` inserts the known name/version; `E8B00D–E8B00E` increments the count. `EB0C60` writes u32LE count followed by a DDL string key and u16LE value for each entry. The empty-map conclusion for Register must not be applied to Login.

After that map, Login writes a token DDL string (`E966FE → EAFCB0`), three u16 fields and one u32 field (`E996C0`, ten bytes total), a Variant, and a StationURL DDL string (`E96716 → EAFC50`). The Variant writes a one-byte tag. Its dispatch table at `EB0484` gives these payload shapes:

| Tag | Additional bytes |
|---|---|
| 0 | None |
| 1, 2, 5, 6 | Eight opaque bytes |
| 3 | One opaque byte |
| 4 | A DDL string |
| 7 | Sixteen GUID wire bytes via `EAFBC0` |

Register writes the empty map, then a u32LE URL count and that many StationURL DDL strings (`E96322–E96351`). Ordinary DDL strings use a u16LE byte length including the final NUL. Interior token, variant and URL bytes can be skipped without decoding them or imposing an ASCII requirement.

The isolated `LoginRpcArgumentShape` validator accepts only the known Login class/version entry or Register's empty map, accepts native null-pointer string length0 for opaque argument strings, restricts Register to1..32 URLs, and caps the body at65,536 bytes. The known class name remains an exact nonnull match; a null Register URL is structurally valid but is not a usable endpoint. The count/body bounds are probe policy, not universal native limits. It requires full body consumption and returns only a Boolean and a fixed failure enum. It does not copy argument values, create strings from input, parse URL/token semantics, return identity material or log argument contents.

## LoginWithToken_V1

The successful method is `LoginProtocol::LoginWithToken_V1*`. Its return parser `E97130` consumes, in order:

1. A 16-byte ProfileID: u32LE, u16LE, u16LE and eight opaque bytes (`EB04F0 → E5A3C0`).
2. A StationURL string (`EB05C0 → EB0630 → E5EBE0`).
3. One byte normalized to a Boolean (`E67230`).

StationURL serialization differs from the smaller header string limit: its DDL string has a u16 length, normally including terminal NUL, up to 65,535 bytes. A native null pointer writes length 0; an ordinary empty string writes length 1 plus NUL. ASCII is unambiguous in the inspected encoding paths; arbitrary non-ASCII configuration is unresolved. A conservative new codec can support only bounded ASCII, non-null strings and describe that as its own restriction.

The return values are registered at LoginClient+0x10/+0x20/+0x88. The first is the local ProfileID (`E88E00`), copied into Credentials+0x0C. A comparison with ProfileID::Null at `E8F591–E8F5CA` asserts a native invariant; it is not an unconditional clean error return. No equivalence to a real Ubisoft account or permission to use arbitrary IDs follows from this parser alone.

The URL's numeric `DID` parameter is copied into Credentials+0x20 (`E8F15D → E5DE40`), with a default of 0 at this read site. Its broader meaning and valid local values need additional validation.

The Boolean means **redirect**, not authentication success. When true, `E8C390` adds `redirected=true` to the copied URL. `E8F0B0` treats any nonempty redirected parameter as a redirect, including one already present when the Boolean is false. It permits one disconnect/reconnect to that URL and then calls RedirectLogin_V1; a second redirect fails. Without that marker it proceeds on the existing connection to RegisterURLs.

## Register_V1 and login completion

The ordinary follow-up is `LoginProtocol::Register_V1`. Its request contains the common request header, a fresh extension map serialized as u32 count 0 (`EB0D00 → EB0C60`), then u32 URL count and that many StationURL strings (`E96310 → EAFC50`). This finding describes the traced ordinary request; it is not an argument parser for arbitrary extension maps.

The successful response method is `LoginProtocol::Register_V1*`. Parser `E97240` consumes exactly u32LE RVCID and a public StationURL. They populate Credentials+0x1C and the job's public URL at +0x1E0. The separate result object at job+0xE0 is initialized locally by `E8C420` before the RPC; it is **not** a third wire return value.

`CompleteLogin` at `E8D990` requires the successful call-context state and its local result checks. It adds the RVCID parameter to the returned public URL (`E5EAE0`), updates applicable external/NAT URL state, stores the URL at Backend+0xA8 and invokes Backend virtual+8 before completing the job. Therefore the first LoginWithToken response alone cannot establish completed login.

The native special ProfileID `00000000-0000-0000-0000-000000000002` skips ordinary registration. Its purpose is unresolved. It must not be treated as a supported offline identity or selected merely to avoid implementing Register_V1.

## Remaining requirements

The [bounded local experiment](LOCAL-LOGIN-PROBE.md) now combines temporary local identity, request assembly and candidate response transport. A compatible service still needs verified client completion, persistent local identities and subsequent game services. Parsing these fields is insufficient evidence that chosen values work. The separate [UbiServices bootstrap dependency](UBISERVICES-BOOTSTRAP.md) remains unresolved for fully offline operation. The static research described here did not send application replies.
