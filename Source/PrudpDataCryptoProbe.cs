using System;
using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;

namespace S7Patcher.Source
{
    // Default HE stream-3 transformation only; never returns plaintext or RPC data.
    internal static class PrudpDataCryptoProbe
    {
        internal const int PlaintextLimit = 65536; // Conservative probe cap, not a native protocol limit.

        internal static PrudpDataCryptoResult Inspect(ReadOnlySpan<byte> packet, PrudpProbePeer peer)
        {
            if (!PrudpDataAckProbeCodec.TryReadRequest(packet, peer, out var data, out _))
                return new() { Outcome = "outside-data-crypto-context" };
            ReadOnlySpan<byte> body = packet.Slice(data.PayloadOffset, data.PayloadLength);
            if (body.IsEmpty) return new() { Outcome = "empty-body-bypassed", SerializedPayloadLength = 0 };
            if (!ValidBodyLength(body.Length))
                return new() { Outcome = "invalid-cbc-length", SerializedPayloadLength = body.Length };
            byte[] key = null;
            try
            {
                key = peer.Connect.DeriveDataKey();
                return InspectBody(body, BinaryPrimitives.ReadUInt16LittleEndian(packet[8..]), key);
            }
            catch (CryptographicException) { return new() { Outcome = "key-derivation-failed", SerializedPayloadLength = body.Length }; }
            catch (PlatformNotSupportedException) { return new() { Outcome = "key-derivation-failed", SerializedPayloadLength = body.Length }; }
            finally { if (key != null) CryptographicOperations.ZeroMemory(key); }
        }

        internal static PrudpDataCryptoResult InspectBody(ReadOnlySpan<byte> body, ushort sequence, ReadOnlySpan<byte> key)
        {
            PrudpDataCryptoResult result = new() { SerializedPayloadLength = body.Length };
            if (body.IsEmpty) return result with { Outcome = "empty-body-bypassed" };
            if (!ValidBodyLength(body.Length)) return result with { Outcome = "invalid-cbc-length" };
            if (key.Length != 16) return result with { Outcome = "invalid-key-length" };
            byte[] iv = null, envelope = null, expanded = null;
            try
            {
                iv = body[..16].ToArray();
                using (Aes aes = Aes.Create())
                {
                    aes.SetKey(key);
                    try { envelope = aes.DecryptCbc(body[16..], iv, PaddingMode.PKCS7); }
                    catch (CryptographicException) { return result with { Outcome = "cbc-padding-or-decryption-failed" }; }
                }
                result = result with { DecryptedEnvelopeLength = envelope.Length };
                if (envelope.Length == 0) return result with { Outcome = "missing-compression-envelope" };
                bool compressed = envelope[0] != 0;
                result = result with { Compressed = compressed };
                ReadOnlySpan<byte> decoded;
                if (!compressed)
                {
                    if (envelope.Length - 1 > PlaintextLimit) return result with { Outcome = "decompression-limit-exceeded" };
                    decoded = envelope.AsSpan(1);
                }
                else
                {
                    // Standard zlib header, no dictionary. Ignore the capacity hint.
                    if (envelope.Length < 9 || (envelope[1] & 15) != 8 || (envelope[1] >> 4) > 7
                        || ((envelope[1] << 8) + envelope[2]) % 31 != 0 || (envelope[2] & 0x20) != 0)
                        return result with { Outcome = "zlib-invalid-or-incomplete" };
                    expanded = new byte[PlaintextLimit + 1];
                    int count = 0;
                    try
                    {
                        using CompleteZlibInput input = new(envelope, 1, envelope.Length - 1);
                        using ZLibStream zlib = new(input, CompressionMode.Decompress);
                        while (count < expanded.Length)
                        {
                            int read = zlib.Read(expanded.AsSpan(count));
                            if (read == 0) break;
                            count += read;
                        }
                    }
                    catch (InvalidDataException) { return result with { Outcome = "zlib-invalid-or-incomplete" }; }
                    if (count > PlaintextLimit) return result with { Outcome = "decompression-limit-exceeded" };
                    decoded = expanded.AsSpan(0, count);
                    // Require the declared final trailer too; trailing bytes do not
                    // become an additional compression stream in this narrow probe.
                    uint a = 1, b = 0;
                    foreach (byte value in decoded) { a = (a + value) % 65521; b = (b + a) % 65521; }
                    if (BinaryPrimitives.ReadUInt32BigEndian(envelope.AsSpan(envelope.Length - 4)) != ((b << 16) | a))
                        return result with { Outcome = "zlib-invalid-or-incomplete" };
                }
                if (decoded.Length < 2) return result with { Outcome = "missing-sequence-suffix" };
                bool matches = BinaryPrimitives.ReadUInt16LittleEndian(decoded[^2..]) == sequence;
                return result with { Outcome = matches ? "decoded-sequence-matched" : "sequence-mismatch",
                    DecodedPayloadLength = decoded.Length - 2, SequenceMatches = matches };
            }
            finally
            {
                if (iv != null) CryptographicOperations.ZeroMemory(iv);
                if (envelope != null) CryptographicOperations.ZeroMemory(envelope);
                if (expanded != null) CryptographicOperations.ZeroMemory(expanded);
            }
        }

        private static bool ValidBodyLength(int length) => length >= 32
            && length <= PrudpHandshakePacketDecoder.MaximumDatagramLength && (length - 16) % 16 == 0;

        // ZLibStream can otherwise treat underlying EOF as successful completion
        // without seeing Z_STREAM_END. A finished inflater returns zero without
        // another input read; an incomplete one must fail rather than silently end.
        private sealed class CompleteZlibInput : MemoryStream
        {
            internal CompleteZlibInput(byte[] buffer, int offset, int count) : base(buffer, offset, count, false) { }
            public override int Read(byte[] buffer, int offset, int count)
            {
                int read = base.Read(buffer, offset, count);
                if (count > 0 && read == 0) throw new InvalidDataException("Incomplete zlib stream");
                return read;
            }
            public override int Read(Span<byte> buffer)
            {
                int read = base.Read(buffer);
                if (!buffer.IsEmpty && read == 0) throw new InvalidDataException("Incomplete zlib stream");
                return read;
            }
        }
    }

    internal readonly record struct PrudpDataCryptoResult
    {
        public string Outcome { get; init; }
        public int? SerializedPayloadLength { get; init; }
        public int? DecryptedEnvelopeLength { get; init; }
        public int? DecodedPayloadLength { get; init; }
        public bool? Compressed { get; init; }
        public bool? SequenceMatches { get; init; }
    }
}
