using System.Buffers.Binary;
using S7Patcher.Source;

int passed = 0;
void Check(bool valid, string message) { if (!valid) throw new Exception(message); passed++; }
byte[] Ddl(byte[] content)
{
    byte[] result = new byte[content.Length + 3];
    BinaryPrimitives.WriteUInt16LittleEndian(result, checked((ushort)(content.Length + 1)));
    content.CopyTo(result, 2); return result;
}
byte[] Login(byte tag, byte[] variant, byte[] token = null, byte[] station = null) =>
    [1, 0, 0, 0, 18, 0, .. "ClientVersionInfo\0"u8, 1, 0,
        .. Ddl(token ?? []), .. new byte[10], tag, .. variant, .. Ddl(station ?? [])];
byte[] Register(params byte[][] urls)
{
    byte[] prefix = new byte[8]; BinaryPrimitives.WriteUInt32LittleEndian(prefix.AsSpan(4), (uint)urls.Length);
    return [.. prefix, .. urls.SelectMany(Ddl)];
}
void Valid(LoginRpcMethod method, byte[] body)
{
    byte[] original = (byte[])body.Clone();
    Check(LoginRpcArgumentShape.TryValidate(method, body, out var error) && error == LoginRpcArgumentShapeFailure.None, "Valid argument shape rejected");
    Check(body.SequenceEqual(original), "Validator mutated caller-owned body");
}
void Invalid(LoginRpcMethod method, byte[] body, LoginRpcArgumentShapeFailure expected)
{
    Check(!LoginRpcArgumentShape.TryValidate(method, body, out var error) && error == expected, "Invalid argument shape accepted or misclassified");
}
byte[] Opaque(int length) => Enumerable.Range(0, length).Select(index => unchecked((byte)(index * 73 + 0x80))).ToArray();
for (byte tag = 0; tag < 8; tag++)
{
    byte[] variant = tag switch { 0 => [], 1 or 2 or 5 or 6 => Opaque(8), 3 => [0xff], 4 => Ddl([0xff, 0, 0x80]), 7 => Opaque(16), _ => throw new Exception() };
    byte[] body = Login(tag, variant, [0xff, 0, 0x81, 0xfe], [0x80, 0, 0xff]);
    Valid(LoginRpcMethod.LoginWithTokenV1, body);
    // Every proper prefix loses at least part of the final required DDL field.
    for (int length = 0; length < body.Length; length++)
        Check(!LoginRpcArgumentShape.TryValidate(LoginRpcMethod.LoginWithTokenV1, body.AsSpan(0, length), out var error)
            && error != LoginRpcArgumentShapeFailure.None, "Truncated login body accepted");
    Invalid(LoginRpcMethod.LoginWithTokenV1, [.. body, 0], LoginRpcArgumentShapeFailure.TrailingBytes);
}
for (int tag = 8; tag <= 255; tag++)
    Invalid(LoginRpcMethod.LoginWithTokenV1, Login((byte)tag, []), LoginRpcArgumentShapeFailure.UnknownVariantTag);
byte[] minimal = Login(0, []);
Valid(LoginRpcMethod.LoginWithTokenV1, minimal); // Empty ordinary strings have length1 including NUL.
Invalid(LoginRpcMethod.Unknown, minimal, LoginRpcArgumentShapeFailure.UnknownMethod);
Invalid((LoginRpcMethod)99, minimal, LoginRpcArgumentShapeFailure.UnknownMethod);
foreach (uint count in new uint[] { 0, 2, uint.MaxValue })
{
    byte[] unsupportedMap = (byte[])minimal.Clone(); BinaryPrimitives.WriteUInt32LittleEndian(unsupportedMap, count);
    Invalid(LoginRpcMethod.LoginWithTokenV1, unsupportedMap, LoginRpcArgumentShapeFailure.UnsupportedExtensionMap);
}
byte[] unknownClass = (byte[])minimal.Clone(); unknownClass[6] ^= 1;
Invalid(LoginRpcMethod.LoginWithTokenV1, unknownClass, LoginRpcArgumentShapeFailure.UnknownClassVersionName);
byte[] wrongVersion = (byte[])minimal.Clone(); wrongVersion[24] = 2;
Invalid(LoginRpcMethod.LoginWithTokenV1, wrongVersion, LoginRpcArgumentShapeFailure.UnsupportedClassVersion);
byte[] zeroClassLength = (byte[])minimal.Clone(); zeroClassLength[4] = 0;
Invalid(LoginRpcMethod.LoginWithTokenV1, zeroClassLength, LoginRpcArgumentShapeFailure.UnknownClassVersionName);
byte[] classTerminator = (byte[])minimal.Clone(); classTerminator[23] = 0xff;
Invalid(LoginRpcMethod.LoginWithTokenV1, classTerminator, LoginRpcArgumentShapeFailure.MissingStringTerminator);
byte[] zeroToken = [.. minimal.AsSpan(0, 26), 0, 0, .. minimal.AsSpan(29)];
Valid(LoginRpcMethod.LoginWithTokenV1, zeroToken);
byte[] unterminatedToken = (byte[])minimal.Clone(); unterminatedToken[28] = 0xff;
Invalid(LoginRpcMethod.LoginWithTokenV1, unterminatedToken, LoginRpcArgumentShapeFailure.MissingStringTerminator);
byte[] hugeToken = (byte[])minimal.Clone(); hugeToken[26] = 0xff; hugeToken[27] = 0xff;
Invalid(LoginRpcMethod.LoginWithTokenV1, hugeToken, LoginRpcArgumentShapeFailure.Truncated);
byte[] zeroVariant = Login(4, [0, 0]);
Valid(LoginRpcMethod.LoginWithTokenV1, zeroVariant);
Invalid(LoginRpcMethod.LoginWithTokenV1, Login(4, [1, 0, 1]), LoginRpcArgumentShapeFailure.MissingStringTerminator);
byte[] zeroStation = [.. minimal.AsSpan(0, minimal.Length - 3), 0, 0];
Valid(LoginRpcMethod.LoginWithTokenV1, zeroStation);
byte[] unterminatedStation = (byte[])minimal.Clone(); unterminatedStation[^1] = 1;
Invalid(LoginRpcMethod.LoginWithTokenV1, unterminatedStation, LoginRpcArgumentShapeFailure.MissingStringTerminator);
foreach (int count in new[] { 1, 2, 32 })
{
    byte[] body = Register(Enumerable.Range(0, count).Select(index => new byte[] { 0xff, 0, (byte)index }).ToArray());
    Valid(LoginRpcMethod.RegisterV1, body);
    for (int length = 0; length < body.Length; length++)
        Check(!LoginRpcArgumentShape.TryValidate(LoginRpcMethod.RegisterV1, body.AsSpan(0, length), out var error)
            && error != LoginRpcArgumentShapeFailure.None, "Truncated Register body accepted");
    Invalid(LoginRpcMethod.RegisterV1, [.. body, 0], LoginRpcArgumentShapeFailure.TrailingBytes);
}
Valid(LoginRpcMethod.RegisterV1, Register(Array.Empty<byte>())); // One empty, ordinary DDL URL.
foreach (uint count in new uint[] { 0, 33, uint.MaxValue })
{
    byte[] body = new byte[8]; BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(4), count);
    Invalid(LoginRpcMethod.RegisterV1, body, LoginRpcArgumentShapeFailure.UrlCountOutOfRange);
}
byte[] registerMap = Register(Array.Empty<byte>()); registerMap[3] = 1;
Invalid(LoginRpcMethod.RegisterV1, registerMap, LoginRpcArgumentShapeFailure.UnsupportedExtensionMap);
Valid(LoginRpcMethod.RegisterV1, [0, 0, 0, 0, 1, 0, 0, 0, 0, 0]);
Invalid(LoginRpcMethod.RegisterV1, [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0xff], LoginRpcArgumentShapeFailure.MissingStringTerminator);
// Exact body cap with a large opaque DDL token; no per-token ASCII or255-byte restriction.
byte[] boundary = Login(0, [], new byte[LoginRpcArgumentShape.MaximumBodyLength - minimal.Length]);
Check(boundary.Length == LoginRpcArgumentShape.MaximumBodyLength, "Boundary fixture length wrong");
Valid(LoginRpcMethod.LoginWithTokenV1, boundary);
Invalid(LoginRpcMethod.LoginWithTokenV1, [.. boundary, 0], LoginRpcArgumentShapeFailure.BodyLimitExceeded);
Invalid(LoginRpcMethod.RegisterV1, new byte[LoginRpcArgumentShape.MaximumBodyLength + 1], LoginRpcArgumentShapeFailure.BodyLimitExceeded);
// Hot validation performs no allocation: tokens/URLs/variants are only skipped.
for (int index = 0; index < 32; index++) LoginRpcArgumentShape.TryValidate(LoginRpcMethod.LoginWithTokenV1, boundary, out _);
long before = GC.GetAllocatedBytesForCurrentThread(); bool allValid = true;
for (int index = 0; index < 1000; index++) allValid &= LoginRpcArgumentShape.TryValidate(LoginRpcMethod.LoginWithTokenV1, boundary, out _);
long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
Check(allValid && allocated == 0, "Validator allocated or materialized opaque argument values");
Console.WriteLine($"PASS: {passed} isolated Login/Register shape checks; all tags, opaque strings, truncation, limits, complete consumption, immutable input and zero allocations.");
