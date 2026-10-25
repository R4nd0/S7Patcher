using System.Buffers.Binary;
using S7Patcher.Source;

internal static class DataDecoderChecks
{
    internal static int Run()
    {
        int passed = 0;
        void Check(bool condition, string message)
        {
            if (!condition) throw new Exception(message);
            passed++;
        }
        static byte[] Packet(byte flags, byte[] payload, uint seed = 0)
        {
            using MemoryStream output = new();
            using BinaryWriter writer = new(output);
            writer.Write(new byte[] { 0x3f, 0x31, (byte)(flags | 2), 0x73 });
            writer.Write(0x44332211u); writer.Write((ushort)0x6655); writer.Write((byte)0x87);
            if ((flags & 0x40) != 0) writer.Write((ushort)payload.Length);
            writer.Write(payload);
            uint sum = seed;
            byte[] contents = output.ToArray();
            for (int index = 0; index < contents.Length; index++)
                sum = unchecked(sum + ((uint)contents[index] << ((index % 4) * 8)));
            writer.Write(sum);
            return output.ToArray();
        }
        PrudpDataMetadata Decode(byte[] packet, uint? seed = null)
        {
            byte[] original = (byte[])packet.Clone();
            Check(PrudpDataPacketDecoder.TryDecode(packet, out var result, out var error, seed), "DATA rejected: " + error);
            Check(packet.SequenceEqual(original), "DATA decoder modified input");
            return result;
        }
        void Reject(byte[] packet, PrudpDataDecodeError expected, uint? seed = null)
        {
            Check(!PrudpDataPacketDecoder.TryDecode(packet, out var result, out var error, seed)
                && error == expected && result == default, "DATA rejection differs: " + error);
        }
        byte[] minimal = Packet(0, []);
        Check(minimal.Length == 15 && BinaryPrimitives.ReadUInt32LittleEndian(minimal.AsSpan(11)) == 0xb7bcb9a5,
            "Minimum DATA fixture disagrees with fixed word sum");
        var plain = Decode(minimal);
        Check(plain.PayloadOffset == 11 && plain.PayloadLength == 0 && plain.BytesConsumed == 15
            && plain.ChecksumVerification == PrudpChecksumVerification.Unverified, "Unsized DATA bounds/unknown seed incorrect");
        Check(Decode(minimal, 0).ChecksumVerification == PrudpChecksumVerification.MatchedSuppliedSeed, "Known DATA checksum not verified");
        Reject(minimal, PrudpDataDecodeError.ChecksumMismatch, 1);
        byte[] sized = Packet(0x40, []);
        var zero = Decode(sized, 0);
        Check(sized.Length == 17 && zero.PayloadOffset == 13 && zero.PayloadLength == 0 && zero.BytesConsumed == 17,
            "Sized empty DATA must be 17 bytes");
        for (int length = 0; length < 15; length++)
            Check(!PrudpDataPacketDecoder.TryDecode(minimal.AsSpan(0, length), out _, out _), "Truncated minimum DATA accepted");
        for (int length = 0; length < 17; length++)
            Check(!PrudpDataPacketDecoder.TryDecode(sized.AsSpan(0, length), out _, out _), "Truncated sized DATA accepted");
        byte[] body = Packet(0xc0, [0x11, 0x22, 0x33, 0x44, 0x55], 0x12345678);
        var decoded = Decode(body, 0x12345678);
        Check(decoded.PayloadOffset == 13 && decoded.PayloadLength == 5 && decoded.BytesConsumed == 22,
            "DATA 0x80 incorrectly parsed a CONNECT key extension");
        for (int length = 0; length < body.Length; length++)
            Check(!PrudpDataPacketDecoder.TryDecode(body.AsSpan(0, length), out _, out _), "Truncated declared DATA body accepted");
        byte[] followed = [.. body, .. minimal];
        Check(Decode(followed, 0x12345678).BytesConsumed == body.Length, "Declared DATA consumed trailing frame or wrong checksum range");
        Check(Decode(Packet(0x80, [1, 2, 3]), 0).PayloadOffset == 11, "Unsized DATA 0x80 consumed key extension");
        byte[] extended = [.. minimal, 1, 2, 3, 4];
        Check(Decode(extended).PayloadLength == 4 && Decode(extended).BytesConsumed == extended.Length, "Unsized DATA must consume supplied buffer");
        Reject(extended, PrudpDataDecodeError.ChecksumMismatch, 0);
        byte[] invalidLength = (byte[])sized.Clone();
        BinaryPrimitives.WriteUInt16LittleEndian(invalidLength.AsSpan(11), ushort.MaxValue);
        Reject(invalidLength, PrudpDataDecodeError.TruncatedPayload);
        for (int part = 0; part <= 255; part++)
        {
            byte[] arbitraryPart = (byte[])minimal.Clone(); arbitraryPart[10] = (byte)part;
            Check(PrudpDataPacketDecoder.TryDecode(arbitraryPart, out _, out _), "Unproven part-number constraint imposed");
        }
        for (byte type = 0; type <= 7; type++)
        {
            if (type == 2) continue;
            byte[] other = (byte[])minimal.Clone(); other[2] = type;
            Reject(other, PrudpDataDecodeError.UnsupportedPacketType);
        }
        Reject(new byte[65508], PrudpDataDecodeError.DatagramTooLarge);
        byte[] maximum = new byte[65507]; maximum[2] = 2;
        Check(Decode(maximum).BytesConsumed == maximum.Length, "Maximum UDP size rejected");
        Random random = new(1702);
        for (int sample = 0; sample < 5000; sample++)
        {
            byte[] packet = new byte[random.Next(250)]; random.NextBytes(packet);
            if (!PrudpDataPacketDecoder.TryDecode(packet, out var accepted, out _)) continue;
            Check(accepted.BytesConsumed >= 15 && accepted.BytesConsumed <= packet.Length
                && accepted.PayloadOffset + accepted.PayloadLength + 4 == accepted.BytesConsumed,
                "Accepted DATA slice escaped its containing buffer");
            Check(accepted.ChecksumVerification == PrudpChecksumVerification.Unverified, "Random DATA claimed checksum validation");
        }
        return passed;
    }
}
