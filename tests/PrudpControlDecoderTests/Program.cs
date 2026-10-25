using System.Buffers.Binary;
using S7Patcher.Source;

int passed = 0;
void Check(bool condition, string reason)
{
    if (!condition) throw new Exception(reason);
    passed++;
}
// Independent byte-weighted sum, including partial words and wrapping.
static uint Sum(ReadOnlySpan<byte> bytes, uint seed)
{
    ulong sum = seed;
    for (int index = 0; index < bytes.Length; index++)
        sum += (ulong)bytes[index] << ((index % 4) * 8);
    return unchecked((uint)sum);
}
static byte[] Packet(byte type, byte flags, byte[] payload, uint seed = 0)
{
    bool sized = (flags & 0x40) != 0;
    byte[] result = new byte[payload.Length + (sized ? 16 : 14)];
    result[0] = 0x3a; result[1] = 0x31; result[2] = (byte)(type | flags); result[3] = 0x56;
    BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4), 0x12345678);
    BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(8), 0x9abc);
    if (sized) BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(10), checked((ushort)payload.Length));
    payload.CopyTo(result, sized ? 12 : 10);
    BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(result.Length - 4), Sum(result.AsSpan(0, result.Length - 4), seed));
    return result;
}
void Reject(byte[] input, PrudpControlDecodeError expected, uint? seed = 0)
{
    byte[] copy = input.ToArray();
    Check(!PrudpControlPacketDecoder.TryDecode(input, out PrudpControlMetadata metadata, out PrudpControlDecodeError error, seed)
        && error == expected, "Wrong rejection outcome");
    Check(metadata.BytesConsumed == 0 && metadata.PacketSignature == 0 && metadata.SequenceId == 0
        && metadata.SourceVirtualPort == 0 && metadata.DestinationVirtualPort == 0 && metadata.SessionId == 0
        && metadata.ChecksumVerification == PrudpChecksumVerification.Unverified, "Failure exposed partial metadata");
    Check(input.SequenceEqual(copy), "Decoder modified caller-owned input");
}
PrudpControlMetadata Decode(byte[] input, uint? seed = 0)
{
    byte[] copy = input.ToArray();
    Check(PrudpControlPacketDecoder.TryDecode(input, out PrudpControlMetadata value, out PrudpControlDecodeError error, seed)
        && error == PrudpControlDecodeError.None, "Valid control packet rejected");
    Check(input.SequenceEqual(copy), "Successful decode modified input");
    Check(value.BytesConsumed == input.Length && value.PayloadOffset + value.PayloadLength + 4 == input.Length,
        "Decoded extent differs from complete packet");
    return value;
}

// Fixed vectors independently calculated from the ten-byte common header.
byte[] disconnect = Convert.FromHexString("3a31035678563412bc9a6e223868");
byte[] ping = Convert.FromHexString("3a31045678563412bc9a6e223968");
foreach ((byte[] input, PrudpControlPacketType type) in new[]
    { (disconnect, PrudpControlPacketType.Disconnect), (ping, PrudpControlPacketType.Ping) })
{
    PrudpControlMetadata metadata = Decode(input);
    Check(metadata.Type == type && metadata.Flags == 0 && metadata.PayloadOffset == 10 && metadata.PayloadLength == 0,
        "Native type mapping or 14-byte empty layout differs");
    Check(metadata.SourceVirtualPort == 0x3a && metadata.DestinationVirtualPort == 0x31 && metadata.SessionId == 0x56
        && metadata.PacketSignature == 0x12345678 && metadata.SequenceId == 0x9abc, "Common header decoding differs");
    Check(metadata.ChecksumVerification == PrudpChecksumVerification.MatchedSuppliedSeed, "Supplied checksum seed not verified");
    Check(metadata.ToString() == nameof(PrudpControlMetadata), "Metadata ToString exposed opaque header values");
    for (int length = 0; length < input.Length; length++)
        Reject(input[..length], length < 10 ? PrudpControlDecodeError.TruncatedHeader : PrudpControlDecodeError.TruncatedControl);
}
for (byte type = 0; type < 8; type++)
    if (type is not (3 or 4)) Reject(Packet(type, 0, []), PrudpControlDecodeError.UnsupportedPacketType);

foreach (byte type in new byte[] { 3, 4 })
    for (int rawFlags = 0; rawFlags <= 0xf8; rawFlags += 8)
    {
        byte flags = (byte)rawFlags;
        bool supported = (flags & 0x80) == 0 && ((flags & 8) == 0 || (flags & 0x30) == 0);
        foreach (byte[] payload in new byte[][] { [], [0x11, 0x22, 0x33] })
        {
            byte[] packet = Packet(type, flags, payload);
            if (!supported) { Reject(packet, PrudpControlDecodeError.UnsupportedFlags); continue; }
            PrudpControlMetadata metadata = Decode(packet);
            Check(metadata.Flags == flags && metadata.PayloadLength == payload.Length
                && metadata.PayloadOffset == ((flags & 0x40) != 0 ? 12 : 10), "Flags or optional-size layout differs");
        }
    }

byte[] sized = Packet(4, 0x48, [1, 2, 3]);
for (int length = 10; length < sized.Length; length++)
    Reject(sized[..length], length < 14 ? PrudpControlDecodeError.TruncatedControl
        : length < 16 ? PrudpControlDecodeError.TruncatedPayloadLength : PrudpControlDecodeError.TruncatedPayload);
byte[] trailing = sized.Concat(new byte[] { 0x99 }).ToArray();
Reject(trailing, PrudpControlDecodeError.TrailingBytes);
byte[] twoPackets = Packet(3, 0x40, []).Concat(ping).ToArray();
Reject(twoPackets, PrudpControlDecodeError.TrailingBytes);
byte[] undersizedDeclaration = sized.ToArray();
BinaryPrimitives.WriteUInt16LittleEndian(undersizedDeclaration.AsSpan(10), 2);
Reject(undersizedDeclaration, PrudpControlDecodeError.TrailingBytes);
byte[] excessiveDeclaration = sized.ToArray();
BinaryPrimitives.WriteUInt16LittleEndian(excessiveDeclaration.AsSpan(10), ushort.MaxValue);
Reject(excessiveDeclaration, PrudpControlDecodeError.TruncatedPayload);

byte[] wrongChecksum = ping.ToArray(); wrongChecksum[^1] ^= 1;
Reject(wrongChecksum, PrudpControlDecodeError.ChecksumMismatch);
Check(Decode(wrongChecksum, null).ChecksumVerification == PrudpChecksumVerification.Unverified,
    "Missing seed was incorrectly treated as zero or verified");
byte[] nonzeroSeed = Packet(3, 0x20, [255, 255, 255, 255, 255], uint.MaxValue);
Decode(nonzeroSeed, uint.MaxValue);
Reject(nonzeroSeed, PrudpControlDecodeError.ChecksumMismatch, 0);
foreach (int length in new[] { 1, 2, 3, 4, 5, 31, 32, 33 })
    Decode(Packet(4, 0x40, Enumerable.Repeat((byte)255, length).ToArray(), uint.MaxValue), uint.MaxValue);
// An unsized frame uses the entire datagram as its extent. Extra bytes cannot
// be distinguished from opaque payload by layout alone; no framing is guessed.
Decode(Packet(3, 0, ping));
Decode(Packet(3, 0, new byte[PrudpHandshakePacketDecoder.MaximumDatagramLength - 14]));
Decode(Packet(4, 0x40, new byte[PrudpHandshakePacketDecoder.MaximumDatagramLength - 16]));
Reject(new byte[PrudpHandshakePacketDecoder.MaximumDatagramLength + 1], PrudpControlDecodeError.DatagramTooLarge);

Random random = new(20261025);
for (int trial = 0; trial < 5000; trial++)
{
    byte[] input = new byte[random.Next(0, 512)]; random.NextBytes(input);
    bool accepted = PrudpControlPacketDecoder.TryDecode(input, out PrudpControlMetadata value, out PrudpControlDecodeError error);
    if (accepted)
    {
        Check(error == PrudpControlDecodeError.None && value.BytesConsumed == input.Length
            && value.PayloadOffset >= 10 && value.PayloadLength >= 0
            && value.PayloadOffset + value.PayloadLength + 4 == input.Length
            && value.ChecksumVerification == PrudpChecksumVerification.Unverified, "Malformed input violated decoder invariants");
    }
    else Check(error != PrudpControlDecodeError.None && value.BytesConsumed == 0, "Malformed rejection had no error or partial extent");
}
Console.WriteLine($"PASS: {passed} isolated passive control-decoder checks; type mapping, flags, complete extent, bounds, seed status and no opaque ToString. No sockets, replies or runtime integration.");
