using System.Buffers.Binary;
using System.Security.Cryptography;
using S7Patcher.Source;

// Every byte below is invented test data. No captured packet, key or token is used.
int passed = 0;
void Check(bool condition, string description)
{
    if (!condition) throw new Exception(description);
    passed++;
}
uint ReferenceSum(byte[] bytes, uint seed)
{
    ulong sum = seed;
    for (int index = 0; index < bytes.Length; index++)
        sum += (ulong)bytes[index] << ((index % 4) * 8);
    return unchecked((uint)sum);
}
byte[] Packet(byte flagsAndType, byte[] signature, byte[] publicKey, byte[] payload, uint seed)
{
    using MemoryStream stream = new();
    using BinaryWriter writer = new(stream);
    writer.Write(new byte[] { 0x31, 0x32, flagsAndType, 0x12 });
    writer.Write(0x11223344u);
    writer.Write((ushort)0x5566);
    writer.Write(0x778899aau);
    if ((flagsAndType & 7) == 1 && (flagsAndType & 0x80) != 0)
    {
        if ((flagsAndType & 8) != 0) { writer.Write((ushort)signature.Length); writer.Write(signature); }
        writer.Write((ushort)publicKey.Length);
        writer.Write(publicKey);
    }
    if ((flagsAndType & 0x40) != 0) writer.Write((ushort)payload.Length);
    writer.Write(payload);
    writer.Write(ReferenceSum(stream.ToArray(), seed));
    return stream.ToArray();
}
PrudpHandshakeMetadata Decode(byte[] bytes, uint? seed = null)
{
    string before = Convert.ToHexString(SHA256.HashData(bytes));
    Check(PrudpHandshakePacketDecoder.TryDecode(bytes, out var result, out var error, seed), "Valid fixture rejected: " + error);
    Check(Convert.ToHexString(SHA256.HashData(bytes)) == before, "Decoder changed its input");
    return result;
}
void Reject(byte[] bytes, PrudpHandshakeDecodeError expected, uint? seed = null)
{
    Check(!PrudpHandshakePacketDecoder.TryDecode(bytes, out var result, out var error, seed) && error == expected && result == default,
        $"Expected {expected}, got {error}");
}

Check(PrudpHandshakePacketDecoder.ComputeChecksum([], 0x12345678) == 0x12345678, "Empty checksum seed");
Check(PrudpHandshakePacketDecoder.ComputeChecksum([1, 2, 3, 4, 5], uint.MaxValue) == 0x04030205, "LE words/remainder/wrap");
Check(PrudpHandshakePacketDecoder.ComputeChecksum([1, 2], 0) == 0x201, "Two-byte remainder");
Check(PrudpHandshakePacketDecoder.ComputeChecksum([1, 2, 3], 0) == 0x30201, "Three-byte remainder");

const uint testSeed = 0x01020304;
byte[] syn = Packet(0x20, [], [], [], testSeed);
var basic = Decode(syn);
Check(syn.Length == 18 && basic.Type == PrudpHandshakePacketType.Syn && basic.Flags == 0x20, "SYN fixed header");
Check(basic.SourceVirtualPort == 0x31 && basic.DestinationVirtualPort == 0x32 && basic.SessionId == 0x12, "Byte header fields");
Check(basic.PacketSignature == 0x11223344 && basic.SequenceId == 0x5566 && basic.ConnectionSignature == 0x778899aa, "LE fixed fields");
Check(basic.ChecksumVerification == PrudpChecksumVerification.Unverified, "Unknown checksum seed was treated as verified");
Check(basic.BytesConsumed == 18 && basic.PayloadOffset == 14 && basic.PayloadLength == 0, "SYN bounds");
Check(Decode(syn, testSeed).ChecksumVerification == PrudpChecksumVerification.MatchedSuppliedSeed, "Known test seed did not match");
Reject(syn, PrudpHandshakeDecodeError.ChecksumMismatch, testSeed + 1);

byte[] sizedSyn = Packet(0x60, [], [], [], testSeed);
Check(Decode(sizedSyn, testSeed).BytesConsumed == 20, "Length-prefixed empty SYN");
var synAesFlag = Decode(Packet(0xa0, [], [], [4, 5], testSeed), testSeed);
Check(!synAesFlag.HasCryptoExtension && synAesFlag.PayloadLength == 2, "SYN 0x80 incorrectly consumed CONNECT-only extensions");
var plainConnect = Decode(Packet(0x31, [], [], [4, 5, 6], testSeed), testSeed);
Check(plainConnect.Type == PrudpHandshakePacketType.Connect && !plainConnect.HasCryptoExtension && plainConnect.PayloadLength == 3, "Plain CONNECT payload");
var connect = Decode(Packet(0xb1, [], [1, 2, 3], [4, 5], testSeed), testSeed);
Check(connect.HasCryptoExtension && connect.SignatureLength == 0 && connect.PublicKeyOffset == 16 && connect.PublicKeyLength == 3 && connect.PayloadLength == 2,
    "CONNECT request must have a key but no server signature");

// Opaque signature length is explicit, not assumed to be a valid 64-byte signature.
byte[] ack = Packet(0xc9, [9, 8, 7, 6, 5], [1, 2, 3], [4, 5, 6], testSeed);
var aesAck = Decode(ack, testSeed);
Check(aesAck.SignatureOffset == 16 && aesAck.SignatureLength == 5 && aesAck.PublicKeyOffset == 23 && aesAck.PublicKeyLength == 3,
    "CONNECT ACK extension order");
Check(aesAck.PayloadOffset == 28 && aesAck.PayloadLength == 3 && aesAck.BytesConsumed == 35, "CONNECT ACK payload bounds");
for (int length = 0; length < ack.Length; length++)
    Check(!PrudpHandshakePacketDecoder.TryDecode(ack.AsSpan(0, length), out _, out _), "Truncated sized CONNECT accepted at " + length);

byte[] followed = [.. ack, .. syn];
var first = Decode(followed, testSeed);
Check(first.BytesConsumed == ack.Length, "Sized packet consumed unrelated trailing bytes");
Check(PrudpHandshakePacketDecoder.TryDecode(followed.AsSpan(first.BytesConsumed), out var following, out _, testSeed)
    && following.Type == PrudpHandshakePacketType.Syn, "Caller cannot separately decode the remaining bytes");
byte[] implicitPayload = [.. syn, 0x11, 0x22, 0x33, 0x44];
Check(Decode(implicitPayload).BytesConsumed == implicitPayload.Length, "Unsized packet must use the containing buffer end");
Reject(implicitPayload, PrudpHandshakeDecodeError.ChecksumMismatch, testSeed);

Reject(new byte[PrudpHandshakePacketDecoder.MaximumDatagramLength + 1], PrudpHandshakeDecodeError.DatagramTooLarge);
for (byte type = 2; type <= 7; type++)
{
    byte[] unsupported = (byte[])syn.Clone(); unsupported[2] = type;
    Reject(unsupported, PrudpHandshakeDecodeError.UnsupportedPacketType);
}
Reject(Packet(0x81, [], [], [], 0), PrudpHandshakeDecodeError.EmptyCryptoField);
Reject(Packet(0x89, [], [1], [], 0), PrudpHandshakeDecodeError.EmptyCryptoField);
byte[] tooLongKey = Packet(0x81, [], [1], [], 0);
BinaryPrimitives.WriteUInt16LittleEndian(tooLongKey.AsSpan(14, 2), ushort.MaxValue);
Reject(tooLongKey, PrudpHandshakeDecodeError.TruncatedCryptoField);
byte[] tooLongPayload = (byte[])sizedSyn.Clone();
BinaryPrimitives.WriteUInt16LittleEndian(tooLongPayload.AsSpan(14, 2), ushort.MaxValue);
Reject(tooLongPayload, PrudpHandshakeDecodeError.TruncatedPayload);

// Bounded deterministic malformed-input coverage: neither throws nor leaks slices.
Random random = new(710);
for (int sample = 0; sample < 5000; sample++)
{
    byte[] bytes = new byte[random.Next(300)]; random.NextBytes(bytes);
    if (PrudpHandshakePacketDecoder.TryDecode(bytes, out var decoded, out var error))
    {
        Check(error == PrudpHandshakeDecodeError.None && decoded.BytesConsumed >= 18 && decoded.BytesConsumed <= bytes.Length,
            "Accepted input has invalid packet bounds");
        Check(decoded.PayloadOffset + decoded.PayloadLength + 4 == decoded.BytesConsumed, "Accepted payload extends outside packet");
        Check(decoded.SignatureOffset + decoded.SignatureLength <= decoded.PayloadOffset && decoded.PublicKeyOffset + decoded.PublicKeyLength <= decoded.PayloadOffset,
            "Accepted crypto slice exceeds payload start");
        Check(decoded.ChecksumVerification == PrudpChecksumVerification.Unverified, "Random input was authenticated without a supplied seed");
    }
}
Console.WriteLine($"PASS: {passed} decoder checks plus 5000 malformed-input samples; invented fixtures only, no networking or game data.");
