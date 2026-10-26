using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace S7Patcher.Source
{
    // Real-record candidate, not enabled by the ordinary service yet. Public
    // sessions only; no reservations, invitations, ranking or membership mutation.
    internal static class LocalSessionCatalogueCodec
    {
        private static string Key(string text) => Convert.ToHexString(Encoding.ASCII.GetBytes(text));

        internal static bool TrySearch(ReadOnlySpan<byte> request, LocalSessionRegistry registry, object requester,
            out byte[] response, out string reason)
        {
            response = null; reason = "unsupported-catalogue-query";
            if (requester == null || !LocalSessionSearchCodec.TryReadQuery(request, out var query)) return false;
            using (query)
            {
                if (!query.Selector.AsSpan().SequenceEqual("default_query"u8)) return false;
                // Local policy: search_score is a ranking hint; stable session-ID
                // order is used instead. Other filters are exact typed equality.
                if (query.Filters.TryGetValue(Key("search_score"), out var score)
                    && (score.Length != 9 || score[0] != 1)) return false;
                var snapshots = registry.CopyCatalogue(requester, query.Space);
                try
                {
                    var selected = new List<LocalSessionRegistry.DisplaySnapshot>();
                    foreach (var snapshot in snapshots)
                    {
                        if (selected.Count >= query.Limit) break;
                        if (!IsPublic(snapshot.Metadata) || !Matches(snapshot.Metadata, query.Filters)) continue;
                        reason = "catalogue-record-incomplete";
                        if (!Complete(snapshot)) return false;
                        selected.Add(snapshot);
                    }
                    using var writer = new LocalSessionDisplayCodec.Writer();
                    Header(writer, request, "MatchmakingProtocol::SearchSessions_V1*"u8);
                    writer.U32((uint)selected.Count);
                    foreach (var snapshot in selected) LocalSessionDisplayCodec.WriteSession(writer, snapshot);
                    writer.U32((uint)selected.Count);
                    foreach (var snapshot in selected)
                    { writer.U32(snapshot.Id); writer.Text(snapshot.Metadata.Creation.StationUrls); }
                    reason = "catalogue-response-too-large";
                    if (!writer.Finish(out response)) return false;
                    reason = "local-live-catalogue-response-created";
                    return true;
                }
                finally { foreach (var snapshot in snapshots) snapshot.Dispose(); }
            }
        }

        internal static bool TryGet(ReadOnlySpan<byte> request, LocalSessionRegistry registry, object requester,
            out byte[] response, out string reason)
        {
            response = null; reason = "unsupported-get-session-arguments";
            if (requester == null || LoginRpcCodec.ClassifyPostLoginRequest(request) != "matchmaking-get-session-v1") return false;
            int offset = 4 + "MatchmakingProtocol".Length + 3 + 1 + 4 + "MatchmakingProtocol::GetSession_V1".Length + 3;
            var body = request[offset..];
            // E51F13 registers both version-1 classes, E51F2E writes Space,
            // E51F40 writes the sole u32 ID. No trailing fields.
            if (body.Length < 4 || BinaryPrimitives.ReadUInt32LittleEndian(body) != 2) return false;
            offset = 4; int classes = 0;
            for (int i = 0; i < 2; i++)
            {
                if (!Text(body, ref offset, out var name) || body.Length - offset < 2
                    || BinaryPrimitives.ReadUInt16LittleEndian(body[offset..]) != 1) return false;
                offset += 2;
                int flag = name.SequenceEqual("MatchmakingSession"u8) ? 1 : name.SequenceEqual("MatchmakingSessionMember"u8) ? 2 : 0;
                if (flag == 0 || (classes & flag) != 0) return false;
                classes |= flag;
            }
            if (!Text(body, ref offset, out var space) || body.Length - offset != 4) return false;
            uint id = BinaryPrimitives.ReadUInt32LittleEndian(body[offset..]);
            reason = "session-not-public-or-not-found";
            if (!registry.TryCopyLiveSession(requester, space, id, out var snapshot)) return false;
            using (snapshot)
            {
                if (!IsPublic(snapshot.Metadata)) return false;
                reason = "catalogue-record-incomplete";
                if (!Complete(snapshot)) return false;
                using var writer = new LocalSessionDisplayCodec.Writer();
                Header(writer, request, "MatchmakingProtocol::GetSession_V1*"u8);
                LocalSessionDisplayCodec.WriteSession(writer, snapshot); // No list count/map.
                reason = "catalogue-response-too-large";
                if (!writer.Finish(out response)) return false;
                reason = "local-get-session-response-created";
                return true;
            }
        }

        private static void Header(LocalSessionDisplayCodec.Writer writer, ReadOnlySpan<byte> request, ReadOnlySpan<byte> method)
        {
            writer.U32(0); writer.Text("MatchmakingProtocol"u8);
            writer.Bytes([0, 1]); writer.Bytes(request.Slice(27, 4)); writer.Text(method);
        }

        private static bool Text(ReadOnlySpan<byte> bytes, ref int offset, out ReadOnlySpan<byte> text)
        {
            text = default;
            if (bytes.Length - offset < 2) return false;
            int length = BinaryPrimitives.ReadUInt16LittleEndian(bytes[offset..]); offset += 2;
            if (length == 0) return true;
            if (length > bytes.Length - offset || bytes[offset + length - 1] != 0) return false;
            text = bytes.Slice(offset, length - 1); offset += length; return true;
        }

        private static bool IsPublic(LocalSessionMetadata metadata) =>
            metadata.Attributes.TryGetValue(Key("private"), out var value) && value.AsSpan().SequenceEqual(new byte[] { 3, 0 });

        private static bool Complete(LocalSessionRegistry.DisplaySnapshot snapshot) =>
            LocalSessionDisplayCodec.HasNativeAttributes(snapshot.Metadata)
            && snapshot.Metadata.Creation != null && !snapshot.Metadata.Creation.StationUrls.IsEmpty;

        private static bool Matches(LocalSessionMetadata metadata, Dictionary<string, byte[]> filters)
        {
            foreach (var pair in filters)
            {
                if (pair.Key == Key("search_score")) continue;
                if (!metadata.Attributes.TryGetValue(pair.Key, out var value) || !value.AsSpan().SequenceEqual(pair.Value)) return false;
            }
            return true;
        }
    }
}
