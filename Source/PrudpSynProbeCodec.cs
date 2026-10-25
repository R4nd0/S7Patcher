using System;
using System.Buffers.Binary;

namespace S7Patcher.Source
{
    // Bounded experiment matching the verified HE SYN-ACK construction only.
    // No connection state, CONNECT response or authentication is implemented.
    internal static class PrudpSynProbeCodec
    {
        internal static bool TryReadRequest(ReadOnlySpan<byte> packet, out PrudpHandshakeMetadata request)
        {
            if (!PrudpHandshakePacketDecoder.TryDecode(packet, out request, out _, 0)) return false;
            // Stream 3 / destination sid 1 is this local configuration's scope.
            // Restrict flags to the observed constructor plus optional length.
            if (request.Type != PrudpHandshakePacketType.Syn || request.Flags is not (0x20 or 0x60)
                || request.SourceVirtualPort >> 4 != 3 || request.DestinationVirtualPort != 0x31
                || request.PayloadLength != 0 || request.BytesConsumed != packet.Length)
            {
                request = default;
                return false;
            }
            return true;
        }

        internal static byte[] CreateReply(in PrudpHandshakeMetadata request, uint cookie)
        {
            if (cookie == 0) throw new ArgumentOutOfRangeException(nameof(cookie));
            byte[] reply = new byte[18];
            reply[0] = request.DestinationVirtualPort;
            reply[1] = request.SourceVirtualPort;
            reply[2] = 0x08; // SYN ACK. Session and packet signature remain zero.
            BinaryPrimitives.WriteUInt16LittleEndian(reply.AsSpan(8), request.SequenceId);
            BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(10), cookie);
            BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(14),
                PrudpHandshakePacketDecoder.ComputeChecksum(reply.AsSpan(0, 14), 0));
            return reply;
        }
    }
}
