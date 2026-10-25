using System;
using System.Buffers.Binary;

namespace S7Patcher.Source
{
    // Native EBBC75..EBBD1D acknowledges transport before deferred decryption.
    // This narrow probe never interprets payloads or produces application replies.
    internal static class PrudpDataAckProbeCodec
    {
        internal static PrudpDataContext GetContext(ReadOnlySpan<byte> packet, PrudpProbePeer peer)
        {
            if (packet.Length < 15) return default;
            return new()
            {
                KnownPeer = peer != null,
                ConnectReplySent = peer?.ConnectReplySent ?? false,
                RoutingMatches = peer == null ? null : packet[0] == peer.SourceVirtualPort && packet[1] == 0x31,
                ClientSessionMatches = peer?.Connect?.MatchesClientSession(packet[3]),
                HeaderCookieMatches = peer == null ? null : BinaryPrimitives.ReadUInt32LittleEndian(packet[4..]) == peer.Cookie
            };
        }

        internal static bool TryCreateReply(ReadOnlySpan<byte> packet, PrudpProbePeer peer, out byte[] reply, out string rejectionReason)
        {
            reply = null;
            if (!TryReadRequest(packet, peer, out _, out rejectionReason)) return false;
            reply = peer.Connect.CreateDataAck(packet);
            return true;
        }

        internal static bool TryReadRequest(ReadOnlySpan<byte> packet, PrudpProbePeer peer,
            out PrudpDataMetadata data, out string rejectionReason)
        {
            rejectionReason = "invalid-structure-or-checksum";
            if (!PrudpDataPacketDecoder.TryDecode(packet, out data, out _, 0)) return false;
            if ((packet[2] & 0xf8) is not (0x20 or 0x30 or 0x60 or 0x70))
            { rejectionReason = "outside-data-ack-flags"; return false; }
            if (data.BytesConsumed != packet.Length)
            { rejectionReason = "trailing-frame"; return false; }
            if (peer?.SynReplySent != true || peer.ConnectReplySent != true || peer.Connect == null)
            { rejectionReason = "missing-connect-context"; return false; }
            PrudpDataContext context = GetContext(packet, peer);
            if (peer.SourceVirtualPort >> 4 != 3 || context.RoutingMatches != true
                || context.ClientSessionMatches != true || context.HeaderCookieMatches != true)
            { rejectionReason = "data-context-mismatch"; return false; }
            rejectionReason = null;
            return true;
        }

        internal static byte[] CreateReply(ReadOnlySpan<byte> request, byte serverSession, uint clientCookie)
        {
            if (request.Length < 11 || serverSession == 0) throw new ArgumentException("Incomplete DATA ACK context");
            byte[] reply = new byte[15];
            reply[0] = request[1]; reply[1] = request[0]; reply[2] = 0x0a; reply[3] = serverSession;
            BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(4), clientCookie);
            request.Slice(8, 3).CopyTo(reply.AsSpan(8)); // Echo current sequence and uninterpreted part byte.
            BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(11),
                PrudpHandshakePacketDecoder.ComputeChecksum(reply.AsSpan(0, 11), 0));
            return reply;
        }
    }

    internal readonly record struct PrudpDataContext
    {
        public bool KnownPeer { get; init; }
        public bool ConnectReplySent { get; init; }
        public bool? RoutingMatches { get; init; }
        public bool? ClientSessionMatches { get; init; }
        public bool? HeaderCookieMatches { get; init; }
    }
}
