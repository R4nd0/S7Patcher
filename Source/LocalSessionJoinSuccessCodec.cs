using System;
using System.Buffers.Binary;

namespace S7Patcher.Source
{
    internal static class LocalSessionJoinSuccessCodec
    {
        internal static bool TryReply(ReadOnlySpan<byte> request, LocalSessionRegistry registry,
            object owner, LocalLoginRpcEngine registration, out byte[] response, out string reason)
        {
            response = null; reason = "unsupported-join-success-header";
            if (LoginRpcCodec.ClassifyPostLoginRequest(request) != "matchmaking-report-join-success-v1") return false;
            int offset = 31 + 3 + "MatchmakingProtocol::ReportJoinSuccess_V1".Length;
            // E532D6..E53303: empty class map, Space, kind, session ID.
            // D3F954/E4E2C0 supplies kind zero on this native join path.
            // E55675..E556BE recognizes the reply without reading return fields.
            uint call = BinaryPrimitives.ReadUInt32LittleEndian(request.Slice(27, 4));
            using var writer = new LocalSessionDisplayCodec.Writer();
            writer.U32(0); writer.Text("MatchmakingProtocol"u8); writer.Bytes([0, 1]); writer.U32(call);
            writer.Text("MatchmakingProtocol::ReportJoinSuccess_V1*"u8);
            if (!writer.Finish(out var encoded)) { reason = "local-join-success-response-limit"; return false; }
            if (!registry.TryConfirmJoin(owner, registration, request[offset..], out reason))
            { System.Security.Cryptography.CryptographicOperations.ZeroMemory(encoded); return false; }
            response = encoded; return true;
        }
    }

    internal sealed partial class LocalSessionRegistry
    {
        internal bool TryConfirmJoin(object owner, LocalLoginRpcEngine registration,
            ReadOnlySpan<byte> body, out string reason)
        {
            reason = "unsupported-join-success-arguments";
            if (closed || !CatalogueProbe || owner == null || registration == null
                || !LocalSessionMetadata.TryReadJoinSuccessBody(body, out var space, out uint id)) return false;
            reason = "local-join-success-not-reserved-caller";
            if (!registration.TryCopyRegisteredPeer(out var peer)) return false;
            using (peer)
                foreach (var entry in entries)
                    if (entry.Id == id && space.SequenceEqual(entry.Space)
                        && entry.Pending.TryGetValue(owner, out var member) && member.Peer.Matches(peer))
                    {
                        reason = member.Confirmed ? "local-join-success-replayed" : "local-join-member-confirmed";
                        member.Confirmed = true; return true;
                    }
            return false;
        }
    }
}
