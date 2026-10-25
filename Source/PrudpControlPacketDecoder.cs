using System;
using System.Buffers.Binary;

namespace S7Patcher.Source
{
    // Passive, complete-single-packet scope. Native jump table E84A98 maps
    // type3 to DISCONNECT and type4 to PING. Both have the ten-byte common
    // header, optional size/payload and checksum; neither has DATA's part byte.
    // This decoder does not accept a connection, interpret a payload, or reply.
    internal static class PrudpControlPacketDecoder
    {
        internal static bool TryDecode(ReadOnlySpan<byte> buffer, out PrudpControlMetadata metadata,
            out PrudpControlDecodeError error, uint? checksumSeed = null)
        {
            metadata = default;
            error = PrudpControlDecodeError.None;
            if (buffer.Length > PrudpHandshakePacketDecoder.MaximumDatagramLength)
                return Fail(PrudpControlDecodeError.DatagramTooLarge, out error);
            if (buffer.Length < 10)
                return Fail(PrudpControlDecodeError.TruncatedHeader, out error);
            byte type = (byte)(buffer[2] & 7);
            if (type is not (3 or 4))
                return Fail(PrudpControlDecodeError.UnsupportedPacketType, out error);
            byte flags = (byte)(buffer[2] & 0xf8);
            // This supported subset is deliberately narrower than a claim about
            // all native legal combinations. 0x80 and ACK+reliable/request are
            // unsupported here; no CONNECT extension is inferred for controls.
            if ((flags & 0x80) != 0 || ((flags & 8) != 0 && (flags & 0x30) != 0))
                return Fail(PrudpControlDecodeError.UnsupportedFlags, out error);
            if (buffer.Length < 14)
                return Fail(PrudpControlDecodeError.TruncatedControl, out error);

            int payloadOffset = 10;
            int payloadLength;
            int consumed;
            if ((flags & 0x40) != 0)
            {
                if (buffer.Length < 16)
                    return Fail(PrudpControlDecodeError.TruncatedPayloadLength, out error);
                payloadOffset = 12;
                payloadLength = BinaryPrimitives.ReadUInt16LittleEndian(buffer.Slice(10, 2));
                if (payloadLength > buffer.Length - 16)
                    return Fail(PrudpControlDecodeError.TruncatedPayload, out error);
                consumed = payloadLength + 16;
                // Native size parsing can select a prefix of a larger buffer.
                // This isolated observer supports exactly one complete packet.
                if (consumed != buffer.Length)
                    return Fail(PrudpControlDecodeError.TrailingBytes, out error);
            }
            else
            {
                payloadLength = buffer.Length - 14;
                consumed = buffer.Length;
            }
            uint checksum = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(consumed - 4, 4));
            if (checksumSeed.HasValue && PrudpHandshakePacketDecoder.ComputeChecksum(
                buffer[..(consumed - 4)], checksumSeed.Value) != checksum)
                return Fail(PrudpControlDecodeError.ChecksumMismatch, out error);

            metadata = new()
            {
                Type = (PrudpControlPacketType)type, Flags = flags,
                SourceVirtualPort = buffer[0], DestinationVirtualPort = buffer[1], SessionId = buffer[3],
                PacketSignature = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(4, 4)),
                SequenceId = BinaryPrimitives.ReadUInt16LittleEndian(buffer.Slice(8, 2)),
                PayloadOffset = payloadOffset, PayloadLength = payloadLength, BytesConsumed = consumed,
                Checksum = checksum, ChecksumVerification = checksumSeed.HasValue
                    ? PrudpChecksumVerification.MatchedSuppliedSeed : PrudpChecksumVerification.Unverified
            };
            return true;
        }

        private static bool Fail(PrudpControlDecodeError failure, out PrudpControlDecodeError error)
        {
            error = failure;
            return false;
        }
    }

    internal enum PrudpControlPacketType { Disconnect = 3, Ping = 4 }
    internal enum PrudpControlDecodeError
    {
        None, DatagramTooLarge, TruncatedHeader, UnsupportedPacketType, UnsupportedFlags,
        TruncatedControl, TruncatedPayloadLength, TruncatedPayload, TrailingBytes, ChecksumMismatch
    }

    // Ordinary struct, not a record: never synthesize a ToString containing
    // opaque routing fields. Callers may compare these internally to their own
    // stored peer context; a match is not authentication or native acceptance.
    internal readonly struct PrudpControlMetadata
    {
        internal PrudpControlPacketType Type { get; init; }
        internal byte Flags { get; init; }
        internal byte SourceVirtualPort { get; init; }
        internal byte DestinationVirtualPort { get; init; }
        internal byte SessionId { get; init; }
        internal uint PacketSignature { get; init; }
        internal ushort SequenceId { get; init; }
        internal int PayloadOffset { get; init; }
        internal int PayloadLength { get; init; }
        internal int BytesConsumed { get; init; }
        internal uint Checksum { get; init; }
        internal PrudpChecksumVerification ChecksumVerification { get; init; }
        public override string ToString() => nameof(PrudpControlMetadata);
    }
}
