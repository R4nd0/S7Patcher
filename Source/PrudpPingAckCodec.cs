using System;

namespace S7Patcher.Source
{
    // Native EBBC75..EBBD1D echoes type/sequence with ACK bit 0x08.
    // This subset accepts only empty, non-reliable PING requests. Reliable
    // controls would also consume the ordered sequence space and remain unsupported.
    internal static class PrudpPingAckCodec
    {
        internal static bool TryCreateReply(ReadOnlySpan<byte> packet, PrudpProbePeer peer, out byte[] reply)
        {
            reply = null;
            if (!PrudpControlPacketDecoder.TryDecode(packet, out var control, out _, 0)
                || control.Type != PrudpControlPacketType.Ping || control.Flags is not (0x20 or 0x60)
                || control.PayloadLength != 0 || control.BytesConsumed != packet.Length
                || peer?.SynReplySent != true || peer.ConnectReplySent != true || peer.Connect == null
                || peer.SourceVirtualPort >> 4 != 3 || control.SourceVirtualPort != peer.SourceVirtualPort
                || control.DestinationVirtualPort != 0x31 || control.PacketSignature != peer.Cookie
                || !peer.Connect.MatchesClientSession(control.SessionId)) return false;
            reply = peer.Connect.CreatePingAck(control.SequenceId);
            return true;
        }
    }
}
