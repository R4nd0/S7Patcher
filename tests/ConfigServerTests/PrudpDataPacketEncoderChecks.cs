using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using S7Patcher.Source;

internal static class PrudpDataPacketEncoderChecks
{
    internal static int Run()
    {
        if (!OperatingSystem.IsWindows())
        { Console.WriteLine("SKIP: DATA encoder BCrypt interoperability requires Windows."); return 0; }
        int passed = 0;
        void Check(bool valid, string message) { if (!valid) throw new Exception(message); passed++; }
        void Reject(Action action)
        { try { action(); throw new Exception("Invalid encoder input accepted"); } catch (ArgumentException) { passed++; } }
        byte[] key = RandomNumberGenerator.GetBytes(16), originalKey = (byte[])key.Clone();
        const uint cookie = 0x87654321;
        const ushort sequence = 0xabcd;
        byte[] Encode(byte[] plain, bool compress = true, ushort seq = sequence, byte part = 0xfe) =>
            PrudpDataPacketEncoder.Encode(0x31, 0x3a, 0x67, cookie, seq, part, plain, key, compress);
        try
        {
            foreach ((byte[] plaintext, bool compression, bool expectedCompressed) in new[] {
                (Array.Empty<byte>(), true, false), (new byte[] { 0x42 }, true, false),
                (new byte[512], true, true), (new byte[947], true, true),
                (new byte[947], false, false), (RandomNumberGenerator.GetBytes(947), true, false) })
            {
                byte[] original = (byte[])plaintext.Clone();
                byte[] packet = Encode(plaintext, compression);
                Check(packet.AsSpan(0, 11).SequenceEqual(new byte[] { 0x31, 0x3a, 0x32, 0x67, 0x21, 0x43, 0x65, 0x87, 0xcd, 0xab, 0xfe }), "Wrong exact DATA header");
                uint checksum = 0;
                for (int index = 0; index < packet.Length - 4; index++)
                    checksum = unchecked(checksum + ((uint)packet[index] << ((index % 4) * 8)));
                Check(BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(packet.Length - 4)) == checksum, "Independent seed0 checksum mismatch");
                Check(PrudpDataPacketDecoder.TryDecode(packet, out var decoded, out _, 0)
                    && decoded.BytesConsumed == packet.Length && decoded.PayloadOffset == 11
                    && decoded.PayloadLength == packet.Length - 15, "Decoder did not consume exact encoder output");
                Check(decoded.PayloadLength >= 32 && (decoded.PayloadLength - 16) % 16 == 0 && packet.Length <= 991, "Invalid encrypted body size");
                byte[] iv = packet.AsSpan(11, 16).ToArray();
                byte[] envelope = NativeCngFixtures.Decrypt(packet.AsSpan(27, decoded.PayloadLength - 16).ToArray(), key, iv);
                byte[] expanded = null;
                try
                {
                    Check((envelope[0] != 0) == expectedCompressed, "Compression selection mismatch");
                    if (envelope[0] == 0) expanded = envelope.AsSpan(1).ToArray();
                    else
                    {
                        using MemoryStream source = new(envelope, 1, envelope.Length - 1, false);
                        using ZLibStream inflater = new(source, CompressionMode.Decompress);
                        using MemoryStream output = new(); inflater.CopyTo(output); expanded = output.ToArray();
                        Check(envelope.Length - 1 < plaintext.Length + 2, "Compressed envelope was not shorter");
                    }
                    Check(expanded.Length == plaintext.Length + 2 && expanded.AsSpan(0, plaintext.Length).SequenceEqual(plaintext)
                        && BinaryPrimitives.ReadUInt16LittleEndian(expanded.AsSpan(expanded.Length - 2)) == sequence,
                        "Native CBC decrypt plus independent envelope decode failed");
                    var observed = PrudpDataCryptoProbe.InspectBody(packet.AsSpan(11, decoded.PayloadLength), sequence, key);
                    Check(observed.Outcome == "decoded-sequence-matched" && observed.DecodedPayloadLength == plaintext.Length
                        && observed.Compressed == expectedCompressed, "Existing crypto decoder rejected encoder output");
                    Check(PrudpDataCryptoProbe.InspectBody(packet.AsSpan(11, decoded.PayloadLength), 0xabce, key).Outcome == "sequence-mismatch", "Encoded suffix not bound to sequence");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(iv); CryptographicOperations.ZeroMemory(envelope);
                    if (expanded != null) CryptographicOperations.ZeroMemory(expanded);
                }
                Check(plaintext.SequenceEqual(original) && key.SequenceEqual(originalKey), "Encoder mutated caller-owned plaintext or key");
                byte[] again = Encode(plaintext, compression);
                Check(!packet.AsSpan(11, 16).SequenceEqual(again.AsSpan(11, 16)), "IV reused across independent encodings");
                if (plaintext.Length == 0) Check(packet.Length == 47 && packet[2] == 0x32, "Empty application DATA became an empty ACK");
                CryptographicOperations.ZeroMemory(plaintext); CryptographicOperations.ZeroMemory(original);
            }
            foreach (ushort seq in new ushort[] { 0, 65535 })
            foreach (byte part in new byte[] { 0, 1, 255 })
            {
                byte[] packet = Encode([], false, seq, part);
                Check(BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(8)) == seq && packet[10] == part
                    && PrudpDataCryptoProbe.InspectBody(packet.AsSpan(11, packet.Length - 15), seq, key).SequenceMatches == true,
                    "Boundary sequence or part altered");
            }
            Reject(() => Encode(new byte[948]));
            Reject(() => PrudpDataPacketEncoder.Encode(0x32, 0x3a, 1, 0, 0, 0, [], key));
            Reject(() => PrudpDataPacketEncoder.Encode(0x31, 0x2a, 1, 0, 0, 0, [], key));
            Reject(() => PrudpDataPacketEncoder.Encode(0x31, 0x3a, 0, 0, 0, 0, [], key));
            foreach (int length in new[] { 0, 15, 17, 32 })
                Reject(() => PrudpDataPacketEncoder.Encode(0x31, 0x3a, 1, 0, 0, 0, [], new byte[length]));
            return passed;
        }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(originalKey); }
    }
}
