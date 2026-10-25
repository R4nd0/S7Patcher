using System;
using System.Buffers.Binary;

namespace S7Patcher.Source
{
    // Static HE evidence: E86CE0 input / E82380 output, known Ubisoft executable
    // SHA256 4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f.
    // The config server may opt into passive metadata decoding only.
    // Structural decoding is not authentication or a working handshake. No data
    // is logged, no reply is generated, and crypto buffers remain opaque slices.
    internal static class PrudpHandshakePacketDecoder
    {
        internal const int MaximumDatagramLength = 65507;

        internal static bool TryDecode(ReadOnlySpan<byte> buffer, out PrudpHandshakeMetadata metadata,
            out PrudpHandshakeDecodeError error, uint? checksumSeed = null)
        {
            metadata = default;
            error = PrudpHandshakeDecodeError.None;
            if (buffer.Length > MaximumDatagramLength)
                return Fail(PrudpHandshakeDecodeError.DatagramTooLarge, out error);
            if (buffer.Length < 10)
                return Fail(PrudpHandshakeDecodeError.TruncatedHeader, out error);
            byte type = (byte)(buffer[2] & 7);
            if (type > 1)
                return Fail(PrudpHandshakeDecodeError.UnsupportedPacketType, out error);
            if (buffer.Length < 18)
                return Fail(PrudpHandshakeDecodeError.TruncatedHandshake, out error);

            byte flags = (byte)(buffer[2] & 0xf8);
            int position = 14;
            int dataLimit = buffer.Length - 4; // Always reserve the final checksum.
            int signatureOffset = 0, signatureLength = 0, publicKeyOffset = 0, publicKeyLength = 0;
            // E8727D gates this extension on CONNECT, not on 0x80 alone.
            bool hasCryptoExtension = type == 1 && (flags & 0x80) != 0;
            if (hasCryptoExtension)
            {
                if ((flags & 8) != 0 && !ReadOpaqueField(buffer, dataLimit, ref position,
                    out signatureOffset, out signatureLength, out error)) return false;
                if (!ReadOpaqueField(buffer, dataLimit, ref position,
                    out publicKeyOffset, out publicKeyLength, out error)) return false;
            }

            int payloadLength;
            int consumed;
            if ((flags & 0x40) != 0)
            {
                if (position > dataLimit - 2)
                    return Fail(PrudpHandshakeDecodeError.TruncatedPayloadLength, out error);
                payloadLength = BinaryPrimitives.ReadUInt16LittleEndian(buffer.Slice(position, 2));
                position += 2;
                if (payloadLength > dataLimit - position)
                    return Fail(PrudpHandshakeDecodeError.TruncatedPayload, out error);
                // E8793E..E87954 / E87A49: a declared packet may end before the
                // containing buffer. Do not interpret or checksum trailing bytes.
                consumed = position + payloadLength + 4;
            }
            else
            {
                payloadLength = dataLimit - position;
                consumed = buffer.Length;
            }
            uint checksum = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(consumed - 4, 4));
            if (checksumSeed.HasValue && ComputeChecksum(buffer[..(consumed - 4)], checksumSeed.Value) != checksum)
                return Fail(PrudpHandshakeDecodeError.ChecksumMismatch, out error);

            metadata = new()
            {
                Type = (PrudpHandshakePacketType)type, Flags = flags,
                SourceVirtualPort = buffer[0], DestinationVirtualPort = buffer[1], SessionId = buffer[3],
                PacketSignature = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(4, 4)),
                SequenceId = BinaryPrimitives.ReadUInt16LittleEndian(buffer.Slice(8, 2)),
                ConnectionSignature = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(10, 4)),
                HasCryptoExtension = hasCryptoExtension,
                SignatureOffset = signatureOffset, SignatureLength = signatureLength,
                PublicKeyOffset = publicKeyOffset, PublicKeyLength = publicKeyLength,
                PayloadOffset = position, PayloadLength = payloadLength, BytesConsumed = consumed,
                Checksum = checksum,
                ChecksumVerification = checksumSeed.HasValue ? PrudpChecksumVerification.MatchedSuppliedSeed : PrudpChecksumVerification.Unverified
            };
            return true;
        }

        // E6C8A0: wrapping sum of LE32 words, with a zero-padded final word.
        // A caller must supply a separately established stream checksum seed.
        // This is neither CRC nor a cryptographic integrity/authentication check.
        internal static uint ComputeChecksum(ReadOnlySpan<byte> bytes, uint seed)
        {
            uint sum = seed;
            int position = 0;
            while (bytes.Length - position >= 4)
            {
                sum = unchecked(sum + BinaryPrimitives.ReadUInt32LittleEndian(bytes.Slice(position, 4)));
                position += 4;
            }
            uint remainder = 0;
            for (int shift = 0; position < bytes.Length; position++, shift += 8)
                remainder |= (uint)bytes[position] << shift;
            return unchecked(sum + remainder);
        }

        private static bool ReadOpaqueField(ReadOnlySpan<byte> buffer, int limit, ref int position,
            out int offset, out int length, out PrudpHandshakeDecodeError error)
        {
            offset = length = 0;
            error = PrudpHandshakeDecodeError.None;
            if (position > limit - 2)
                return Fail(PrudpHandshakeDecodeError.TruncatedCryptoLength, out error);
            length = BinaryPrimitives.ReadUInt16LittleEndian(buffer.Slice(position, 2));
            position += 2;
            if (length == 0)
                return Fail(PrudpHandshakeDecodeError.EmptyCryptoField, out error);
            if (length > limit - position)
                return Fail(PrudpHandshakeDecodeError.TruncatedCryptoField, out error);
            offset = position;
            position += length;
            return true;
        }

        private static bool Fail(PrudpHandshakeDecodeError failure, out PrudpHandshakeDecodeError error)
        {
            error = failure;
            return false;
        }
    }

    internal enum PrudpHandshakePacketType { Syn = 0, Connect = 1 }
    internal enum PrudpChecksumVerification { Unverified = 0, MatchedSuppliedSeed = 1 }
    internal enum PrudpHandshakeDecodeError
    {
        None, DatagramTooLarge, TruncatedHeader, UnsupportedPacketType, TruncatedHandshake,
        TruncatedCryptoLength, EmptyCryptoField, TruncatedCryptoField,
        TruncatedPayloadLength, TruncatedPayload, ChecksumMismatch
    }

    internal readonly record struct PrudpHandshakeMetadata
    {
        public PrudpHandshakePacketType Type { get; init; }
        public byte Flags { get; init; }
        public byte SourceVirtualPort { get; init; }
        public byte DestinationVirtualPort { get; init; }
        public byte SessionId { get; init; }
        // These are opaque routing fields, not evidence of peer identity.
        public uint PacketSignature { get; init; }
        public ushort SequenceId { get; init; }
        public uint ConnectionSignature { get; init; }
        public bool HasCryptoExtension { get; init; }
        public int SignatureOffset { get; init; }
        public int SignatureLength { get; init; }
        public int PublicKeyOffset { get; init; }
        public int PublicKeyLength { get; init; }
        public int PayloadOffset { get; init; }
        public int PayloadLength { get; init; }
        public int BytesConsumed { get; init; }
        public uint Checksum { get; init; }
        public PrudpChecksumVerification ChecksumVerification { get; init; }
    }
}
