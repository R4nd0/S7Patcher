using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace S7Patcher.Source
{
    // Accepts a bounded pending reservation, NOT a completed peer connection.
    internal static class LocalSessionJoinCodec
    {
        internal static bool TryReply(ReadOnlySpan<byte> request, LocalSessionRegistry registry,
            object owner, LocalLoginRpcEngine registration, out byte[] response, out string reason)
        {
            response = null; reason = "unsupported-join-header";
            if (LoginRpcCodec.ClassifyPostLoginRequest(request) != "matchmaking-join-session-v1") return false;
            int offset = 31 + 3 + "MatchmakingProtocol::JoinSession_V1".Length;
            uint call = BinaryPrimitives.ReadUInt32LittleEndian(request.Slice(27, 4));
            return registry.TryJoin(owner, registration, request[offset..], snapshot => Encode(call, snapshot),
                out response, out reason);
        }

        internal static byte[] Encode(uint call, LocalSessionRegistry.DisplaySnapshot snapshot)
        {
            using var writer = new LocalSessionDisplayCodec.Writer();
            writer.U32(0); writer.Text("MatchmakingProtocol"u8); writer.Bytes([0, 1]); writer.U32(call);
            writer.Text("MatchmakingProtocol::JoinSession_V1*"u8);
            // E55EF0 reads qString first, then one MatchmakingSession (E4F100).
            // Route is the host's original game URL list, never its auth endpoint.
            writer.Text(snapshot.Metadata.Creation.StationUrls);
            LocalSessionDisplayCodec.WriteSession(writer, snapshot);
            return writer.Finish(out var result) ? result : null;
        }
    }

    internal sealed partial class LocalSessionRegistry
    {
        internal bool TryObserveJoinFailure(object owner, LocalLoginRpcEngine registration,
            ReadOnlySpan<byte> message, out uint sessionKind, out int textLength, out string reason)
            => TryObserveJoinFailure(owner, registration, message, out sessionKind, out textLength, out reason, out _);

        internal bool TryObserveJoinFailure(object owner, LocalLoginRpcEngine registration,
            ReadOnlySpan<byte> message, out uint sessionKind, out int textLength, out string reason, out string category)
        {
            category = null;
            sessionKind = 0; textLength = 0; reason = "local-join-failure-shape";
            if (closed || !CatalogueProbe || owner == null || registration == null
                || LoginRpcCodec.ClassifyPostLoginRequest(message) != "matchmaking-report-join-failure-v1") return false;
            int offset = 31 + 3 + "MatchmakingProtocol::ReportJoinFailure_V1".Length;
            if (!LocalSessionMetadata.TryReadJoinFailureBody(message[offset..], out var space, out uint id,
                out uint reported, out int length, out var classified)) return false;
            reason = "local-join-failure-not-pending-caller";
            if (!registration.TryCopyRegisteredPeer(out var peer)) return false;
            using (peer)
                foreach (var entry in entries)
                    if (entry.Id == id && space.SequenceEqual(entry.Space)
                        && entry.Pending.TryGetValue(owner, out var pending) && pending.Peer.Matches(peer))
                    {
                        sessionKind = reported; textLength = length; category = classified;
                        reason = "local-join-failure-observed"; return true;
                    }
            return false;
        }

        private sealed class PendingMember(LocalLoginRpcEngine.RegisteredPeer peer,
            LocalSessionMetadata metadata, ReadOnlySpan<byte> body) : IDisposable
        {
            internal readonly LocalLoginRpcEngine.RegisteredPeer Peer = peer;
            internal readonly LocalSessionMetadata Metadata = metadata;
            internal readonly byte[] Body = body.ToArray();
            internal bool Confirmed;
            public void Dispose() { Peer.Dispose(); Metadata.Dispose(); CryptographicOperations.ZeroMemory(Body); }
        }

        private static string JoinKey(string value) => Convert.ToHexString(Encoding.ASCII.GetBytes(value));
        private static bool Slots(LocalSessionMetadata metadata, string name, out long number)
        {
            number = 0;
            if (!metadata.Attributes.TryGetValue(JoinKey(name), out var value) || value.Length != 9
                || value[0] is not (1 or 6)) return false;
            number = BinaryPrimitives.ReadInt64LittleEndian(value.AsSpan(1));
            return number is >= 0 and <= 4; // Explicit two-PC / up-to-four-slot test policy.
        }

        internal static bool HostRoutesOwned(ReadOnlySpan<byte> bytes, LocalLoginRpcEngine.RegisteredPeer host)
            => HostRoutesOwned(bytes, host, out _);

        internal static bool HostRoutesOwned(ReadOnlySpan<byte> bytes, LocalLoginRpcEngine.RegisteredPeer host,
            out string reason)
        {
            bool valid = TryHostRoutes(bytes, host, out var projection, out reason);
            if (projection != null) CryptographicOperations.ZeroMemory(projection);
            return valid;
        }

#if S7_LOCAL_PAIR_LAB
        internal static bool TryProjectLabCatalogueRoutes(DisplaySnapshot snapshot, out string reason)
        {
            reason = "local-pair-catalogue-host-invalid";
            if (!LocalLoginRpcEngine.PrudpUrl.TryRead(snapshot.Host.PublicUrl, out var registered)) return false;
            if (!registered.Address.Equals(System.Net.IPAddress.Parse("127.0.0.2"))
                && !registered.Address.Equals(System.Net.IPAddress.Parse("127.0.0.3"))) return true;
            if (!TryHostRoutes(snapshot.Metadata.Creation.StationUrls, snapshot.Host, out var routes, out reason)) return false;
            try { snapshot.Metadata.ReplaceCreationRoutes(routes); return true; }
            finally { CryptographicOperations.ZeroMemory(routes); }
        }
#endif

        private static bool TryHostRoutes(ReadOnlySpan<byte> bytes, LocalLoginRpcEngine.RegisteredPeer host,
            out byte[] projection, out string reason)
        {
            projection = null;
            // Fixed classifications only: never include routes, identifiers or raw request bytes.
            reason = "local-join-host-route-empty";
            if (bytes.IsEmpty) return false;
            reason = "local-join-host-route-too-long";
            if (bytes.Length > 2048) return false;
            reason = "local-join-host-route-non-ascii";
            if (!LocalLoginRpcEngine.PrudpUrl.IsSupportedAscii(bytes)) return false;
            reason = "local-join-host-registration-route-invalid";
            if (host == null || !LocalLoginRpcEngine.PrudpUrl.TryRead(host.PublicUrl, out var registered)) return false;
            string[] urls = Encoding.ASCII.GetString(bytes).Split('|');
            var projected = new System.Collections.Generic.List<string>();
            reason = "local-join-host-route-count";
            if (urls.Length is < 1 or > 4) return false;
            foreach (string text in urls)
            {
                if (text.StartsWith("prudp:/RVCID=", StringComparison.Ordinal) && text.Contains("#Storm=", StringComparison.Ordinal))
                {
                    if (!LocalStormRoute.TryProject(text, host, out var storm, out reason)) return false;
                    projected.Add(storm);
                    continue;
                }
                reason = "local-join-host-route-empty-item";
                if (text.Length == 0) return false;
                reason = "local-join-host-route-scheme";
                if (!text.StartsWith("prudp:/", StringComparison.Ordinal)) return false;
                reason = "local-join-host-route-escaped";
                if (text.Contains('%')) return false;
                reason = text.Contains('#') ? "local-join-host-route-section-invalid" : "local-join-host-route-syntax";
                if (!LocalLoginRpcEngine.PrudpUrl.TryReadGameRoute(text, out var url)) return false;
                reason = "local-join-host-route-loopback";
                if (!url.Address.Equals(registered.Address) && System.Net.IPAddress.IsLoopback(url.Address)) return false;
                reason = "local-join-host-route-unspecified";
                if (!url.Address.Equals(registered.Address) && url.Address.Equals(System.Net.IPAddress.Any)) return false;
                reason = "local-join-host-route-address-mismatch";
                if (!url.Address.Equals(registered.Address)) return false;
                reason = "local-join-host-route-redirected";
                if (url.Has("redirected")) return false;
                projected.Add(text);
            }
            projection = Encoding.ASCII.GetBytes(string.Join('|', projected));
            reason = "local-join-host-route-owned";
            return true;
        }

        private static DisplaySnapshot Snapshot(Entry entry, PendingMember extra = null,
            LocalSessionMetadata replacement = null)
        {
            var metadata = (replacement ?? entry.Metadata).Clone();
            var snapshot = new DisplaySnapshot(entry.Id, entry.Space, metadata, entry.Host.Clone());
            foreach (var member in entry.Pending.Values)
                if (!Add(member)) { snapshot.Dispose(); return null; }
            if (extra != null && !Add(extra)) { snapshot.Dispose(); return null; }
            // Keep the existing conservative reservation accounting. A success
            // report alone does not prove the host's slot metadata was updated.
            int reservedProfiles = snapshot.PendingProfiles.Count + snapshot.ConfirmedProfiles.Count;
            if (reservedProfiles > 0 && Slots(metadata, "settlers_free_slots", out long free))
                BinaryPrimitives.WriteInt64LittleEndian(metadata.Attributes[JoinKey("settlers_free_slots")].AsSpan(1),
                    Math.Max(0, free - reservedProfiles));
            return snapshot;

            bool Add(PendingMember member)
            {
                if (!metadata.TryMerge(member.Metadata, out var merged)) return false;
                // Retain the same metadata object owned by the snapshot.
                foreach (var group in merged.Members)
                {
                    if (!metadata.Members.TryGetValue(group.Key, out var target))
                        metadata.Members.Add(group.Key, target = new(StringComparer.Ordinal));
                    foreach (var pair in group.Value)
                    {
                        if (target.Remove(pair.Key, out var old)) CryptographicOperations.ZeroMemory(old);
                        target.Add(pair.Key, (byte[])pair.Value.Clone());
                    }
                }
                merged.Dispose();
                (member.Confirmed ? snapshot.ConfirmedProfiles : snapshot.PendingProfiles).Add(member.Peer.ProfileId.ToArray());
                return true;
            }
        }

        internal bool TryJoin(object owner, LocalLoginRpcEngine registration, ReadOnlySpan<byte> body,
            Func<DisplaySnapshot, byte[]> encode, out byte[] response, out string reason)
        {
            response = null; reason = "unsupported-join-arguments";
            if (closed || !CatalogueProbe || owner == null || encode == null
                || !LocalSessionMetadata.TryReadJoinBody(body, out var space, out uint id, out var metadata)) return false;
            LocalLoginRpcEngine.RegisteredPeer peer = null;
            PendingMember candidate = null;
            byte[] routes = null;
            try
            {
                reason = "local-join-caller-not-registered";
                if (registration == null || !registration.TryCopyRegisteredPeer(out peer)) return false;
                string identity = Convert.ToHexString(peer.ProfileId);
                reason = "local-join-foreign-member-identity";
                foreach (var group in metadata.Members.Values)
                    foreach (string member in group.Keys) if (member != identity) return false;
                Entry selected = null;
                foreach (Entry entry in entries)
                {
                    if (entry.Id == id && space.SequenceEqual(entry.Space)) selected = entry;
                    if (ReferenceEquals(entry.Owner, owner) || (entry.Id != id && entry.Pending.ContainsKey(owner)))
                    { reason = "local-join-caller-already-in-session"; return false; }
                }
                reason = "local-join-session-not-public-or-not-found";
                if (selected == null || !selected.Metadata.Attributes.TryGetValue(JoinKey("private"), out var privacy)
                    || !privacy.AsSpan().SequenceEqual(new byte[] { 3, 0 })) return false;
                reason = "local-join-host-route-missing-creation";
                if (selected.Metadata.Creation == null) return false;
                if (!TryHostRoutes(selected.Metadata.Creation.StationUrls, selected.Host, out routes, out reason)) return false;
                reason = "local-join-identity-collision";
                if (selected.Host.ProfileId.SequenceEqual(peer.ProfileId)) return false;
                bool replay = selected.Pending.TryGetValue(owner, out var previous);
                foreach (var existing in selected.Pending.Values)
                    if (!ReferenceEquals(existing, previous) && existing.Peer.ProfileId.SequenceEqual(peer.ProfileId)) return false;
                reason = "local-join-replay-mismatch";
                if (replay && (!previous.Peer.Matches(peer) || !body.SequenceEqual(previous.Body))) return false;
                if (!replay)
                {
                    reason = "local-join-no-free-slot";
                    if (!Slots(selected.Metadata, "settlers_max_slots", out long max) || max < 2
                        || !Slots(selected.Metadata, "settlers_free_slots", out long free)
                        || free <= selected.Pending.Count || selected.Pending.Count + 1 >= max) return false;
                    candidate = new(peer, metadata, body); peer = null; metadata = null;
                }
                reason = "local-join-response-limit";
                using var snapshot = Snapshot(selected, candidate);
                if (snapshot == null) return false;
                snapshot.Metadata.ReplaceCreationRoutes(routes);
                if ((response = encode(snapshot)) == null) return false;
                // Publish only after a bounded response has been serialized.
                if (candidate != null) { selected.Pending.Add(owner, candidate); candidate = null; }
                reason = replay ? "local-join-reservation-replayed" : "local-join-reservation-created";
                return true;
            }
            finally
            {
                if (routes != null) CryptographicOperations.ZeroMemory(routes);
                candidate?.Dispose(); metadata?.Dispose(); peer?.Dispose();
            }
        }
    }
}
