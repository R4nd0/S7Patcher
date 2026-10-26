using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace S7Patcher.Source
{
    // Explicit one-client wire/display experiment, NEVER a live catalogue.
    // Reuses the caller's last left lobby, not an invented descriptor type or
    // another peer's identity/route. See LOCAL-SESSION-DISPLAY-PROBE.md.
    internal static class LocalSessionDisplayCodec
    {
        internal const string Title = "Anzeigetest - kein Beitritt";
        private static string Key(string text) => Convert.ToHexString(Encoding.ASCII.GetBytes(text));

        internal static bool TryReply(ReadOnlySpan<byte> message, LocalSessionRegistry registry, object owner,
            out byte[] response, out string reason)
        {
            response = null; reason = "display-probe-disabled";
            if (!registry.DisplayProbe) return false;
            reason = "unsupported-search-arguments";
            if (!LocalSessionSearchCodec.TryReadQuery(message, out var query)) return false;
            using (query)
            {
                reason = "unsupported-display-query-selector";
                if (!query.Selector.AsSpan().SequenceEqual("default_query"u8)) return false;
                reason = "nonempty-session-catalogue-not-yet-supported";
                if (registry.Count != 0) return false;
                if (query.Limit == 0 || !registry.TryCopyDisplaySnapshot(owner, out var snapshot))
                    return LocalSessionSearchCodec.TryReply(message, out response, out reason);
                using (snapshot)
                {
                    if (!query.Space.AsSpan().SequenceEqual(snapshot.Space))
                        return LocalSessionSearchCodec.TryReply(message, out response, out reason);
                    // The native Group search shares this RPC. Never inject a
                    // game row into that list. All other filters are deliberately
                    // bypassed ONLY for this labelled, same-owner display probe.
                    if (query.Filters.TryGetValue(Key("string4"), out var kind))
                    {
                        reason = "unsupported-display-kind-filter";
                        if (kind.Length < 4 || kind[0] != 4) return false;
                        if (kind.AsSpan(3, kind.Length - 4).SequenceEqual("Group"u8))
                            return LocalSessionSearchCodec.TryReply(message, out response, out reason);
                    }
                    return TryEncode(message, snapshot, out response, out reason);
                }
            }
        }

        private static bool TryEncode(ReadOnlySpan<byte> request, LocalSessionRegistry.DisplaySnapshot snapshot,
            out byte[] response, out string reason)
        {
            response = null; reason = "display-probe-missing-native-attributes";
            var metadata = snapshot.Metadata;
            if (!HasNativeAttributes(metadata)) return false;
            reason = "display-probe-missing-game-route";
            if (metadata.Creation == null || metadata.Creation.StationUrls.IsEmpty) return false;
            using Writer writer = new();
            writer.U32(0); writer.Text("MatchmakingProtocol"u8);
            writer.Bytes([0, 1]); writer.Bytes(request.Slice(27, 4));
            writer.Text("MatchmakingProtocol::SearchSessions_V1*"u8);
            writer.U32(1); // Exactly one diagnostic session, independent of requested limit > 0.
            WriteSession(writer, snapshot, Title);
            writer.U32(1); writer.U32(snapshot.Id); writer.Text(metadata.Creation.StationUrls);
            reason = "display-probe-response-too-large";
            if (!writer.Finish(out response)) return false;
            reason = "local-session-display-probe-response-created";
            return true;
        }

        internal static bool HasNativeAttributes(LocalSessionMetadata metadata) =>
            Has(metadata, "echo_session_guid", 4) && Has(metadata, "session_descriptor_type", 6)
            && Has(metadata, "settlers_session_name", 4) && Has(metadata, "settlers_map_name", 4)
            && HasInteger(metadata, "settlers_max_slots") && HasInteger(metadata, "settlers_free_slots")
            && HasInteger(metadata, "settlers_extra_version_number");

        internal static void WriteSession(Writer writer, LocalSessionRegistry.DisplaySnapshot snapshot, string title = null)
        {
            var metadata = snapshot.Metadata;
            writer.U32(snapshot.Id);
            // Known native constructor defaults (E4D5B0, 4C7B10). Local DISPLAY
            // policy only: these are not inferred Ubisoft server field meanings.
            writer.U32(0); writer.Text([]); writer.Bytes(new byte[8]);
            writer.U32(0); writer.U32(0); writer.Bytes([0, 0]);
            writer.U32((uint)(1 + snapshot.PendingProfiles.Count)); writer.Bytes(snapshot.Host.ProfileId); writer.U32(2);
            // Local pending policy: constructor-default state 0, not confirmed
            // peer state 3. ReportJoinSuccess/host notification remains separate.
            foreach (var profile in snapshot.PendingProfiles) { writer.Bytes(profile); writer.U32(0); }
            writer.U32((uint)metadata.Attributes.Count);
            foreach (var pair in metadata.Attributes)
            {
                writer.Text(Convert.FromHexString(pair.Key));
                if (title != null && pair.Key == Key("settlers_session_name"))
                { writer.Bytes([4]); writer.Text(Encoding.ASCII.GetBytes(title)); }
                else writer.Bytes(pair.Value);
            }
            writer.U32((uint)metadata.Members.Count);
            foreach (var group in metadata.Members)
            {
                writer.Text(Convert.FromHexString(group.Key)); writer.U32((uint)group.Value.Count);
                foreach (var pair in group.Value)
                { writer.Bytes(Convert.FromHexString(pair.Key)); writer.Bytes(pair.Value); }
            }
        }

        private static bool Has(LocalSessionMetadata metadata, string key, byte tag) =>
            metadata.Attributes.TryGetValue(Key(key), out var value) && value.Length > 0 && value[0] == tag;
        private static bool HasInteger(LocalSessionMetadata metadata, string key) => Has(metadata, key, 1) || Has(metadata, key, 6);

        internal sealed class Writer : IDisposable
        {
            private readonly byte[] bytes = new byte[ReliableResponseQueue.MaximumResponseLength];
            private int position;
            private bool overflow;
            internal void Bytes(ReadOnlySpan<byte> value)
            {
                if (overflow || value.Length > bytes.Length - position) { overflow = true; return; }
                value.CopyTo(bytes.AsSpan(position)); position += value.Length;
            }
            internal void U32(uint value)
            { Span<byte> number = stackalloc byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(number, value); Bytes(number); }
            internal void Text(ReadOnlySpan<byte> value)
            {
                if (value.Length >= ushort.MaxValue) { overflow = true; return; }
                Span<byte> length = stackalloc byte[2];
                BinaryPrimitives.WriteUInt16LittleEndian(length, (ushort)(value.Length + 1));
                Bytes(length); Bytes(value); Bytes([0]);
            }
            internal bool Finish(out byte[] response)
            {
                response = null;
                if (overflow) return false;
                BinaryPrimitives.WriteUInt32LittleEndian(bytes, (uint)(position - 4));
                response = bytes.AsSpan(0, position).ToArray(); return true;
            }
            public void Dispose() => CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
