using System;
using System.Buffers.Binary;

namespace S7Patcher.Source
{
    // Passive layout only: E8783F..E87851 reads DATA's one-byte part field,
    // E8793E..E87954 bounds its serialized payload. No fragment semantics,
    // decryption, routing acceptance or payload integrity is inferred.
    internal static class PrudpDataPacketDecoder
    {
        internal static bool TryDecode(ReadOnlySpan<byte> buffer, out PrudpDataMetadata metadata,
            out PrudpDataDecodeError error, uint? checksumSeed = null)
        {
            metadata = default;
            error = PrudpDataDecodeError.None;
            if (buffer.Length > PrudpHandshakePacketDecoder.MaximumDatagramLength)
                return Fail(PrudpDataDecodeError.DatagramTooLarge, out error);
            if (buffer.Length < 10) return Fail(PrudpDataDecodeError.TruncatedHeader, out error);
            if ((buffer[2] & 7) != 2) return Fail(PrudpDataDecodeError.UnsupportedPacketType, out error);
            if (buffer.Length < 15) return Fail(PrudpDataDecodeError.TruncatedData, out error);
            // DATA has no connection signature or CONNECT key extension.
            // Skip the uninterpreted part byte at 10; do not retain its value.
            int payloadOffset = 11;
            int payloadLength;
            int consumed;
            if ((buffer[2] & 0x40) != 0)
            {
                if (buffer.Length < 17) return Fail(PrudpDataDecodeError.TruncatedPayloadLength, out error);
                payloadOffset = 13;
                payloadLength = BinaryPrimitives.ReadUInt16LittleEndian(buffer.Slice(11, 2));
                if (payloadLength > buffer.Length - 17) return Fail(PrudpDataDecodeError.TruncatedPayload, out error);
                consumed = payloadLength + 17;
            }
            else
            {
                payloadLength = buffer.Length - 15;
                consumed = buffer.Length;
            }
            uint checksum = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(consumed - 4, 4));
            if (checksumSeed.HasValue && PrudpHandshakePacketDecoder.ComputeChecksum(buffer[..(consumed - 4)], checksumSeed.Value) != checksum)
                return Fail(PrudpDataDecodeError.ChecksumMismatch, out error);
            metadata = new()
            {
                PayloadOffset = payloadOffset, PayloadLength = payloadLength, BytesConsumed = consumed,
                Checksum = checksum, ChecksumVerification = checksumSeed.HasValue
                    ? PrudpChecksumVerification.MatchedSuppliedSeed : PrudpChecksumVerification.Unverified
            };
            return true;
        }

        private static bool Fail(PrudpDataDecodeError failure, out PrudpDataDecodeError error)
        {
            error = failure;
            return false;
        }
    }

    internal enum PrudpDataDecodeError
    {
        None, DatagramTooLarge, TruncatedHeader, UnsupportedPacketType, TruncatedData,
        TruncatedPayloadLength, TruncatedPayload, ChecksumMismatch
    }

    internal readonly record struct PrudpDataMetadata
    {
        public int PayloadOffset { get; init; }
        public int PayloadLength { get; init; }
        public int BytesConsumed { get; init; }
        public uint Checksum { get; init; }
        public PrudpChecksumVerification ChecksumVerification { get; init; }
    }
}
