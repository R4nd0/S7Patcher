using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace S7Patcher.Source
{
    // Run-local records only. Called by the single UDP processing loop. Ownership
    // is the registered transport session, never a claimed identity from a body.
    internal sealed partial class LocalSessionRegistry : IDisposable
    {
        internal const int MaximumSessions = 8;
        private readonly List<Entry> entries = new();
        private readonly Dictionary<object, DisplaySnapshot> previews = new(ReferenceEqualityComparer.Instance);
        internal bool DisplayProbe { get; }
        internal bool CatalogueProbe { get; }
        internal LocalSessionRegistry(bool displayProbe = false, bool catalogueProbe = false)
        {
            if (displayProbe && catalogueProbe) throw new ArgumentException("Choose one catalogue mode.");
            DisplayProbe = displayProbe; CatalogueProbe = catalogueProbe;
        }
        private uint nextId = 1;
        private bool closed;
        internal int Count => entries.Count;

        // Owned copies of real live records, never the retired display preview.
        // The transport must require completed registration before calling this.
        internal List<DisplaySnapshot> CopyCatalogue(object requester, ReadOnlySpan<byte> space)
        {
            List<DisplaySnapshot> result = new();
            if (closed || requester == null) return result;
            foreach (Entry entry in entries)
                if (!ReferenceEquals(entry.Owner, requester) && space.SequenceEqual(entry.Space))
                    result.Add(Snapshot(entry));
            return result;
        }

        internal bool TryCopyLiveSession(object requester, ReadOnlySpan<byte> space, uint id, out DisplaySnapshot snapshot)
        {
            snapshot = null;
            if (closed || requester == null) return false;
            foreach (Entry entry in entries)
                if (entry.Id == id && space.SequenceEqual(entry.Space))
                {
                    snapshot = Snapshot(entry);
                    return true;
                }
            return false;
        }

        internal bool TryCreate(object owner, LocalLoginRpcEngine registration, ReadOnlySpan<byte> body, out uint id, out string reason)
        {
            id = 0;
            reason = "unsupported-create-arguments";
            if (closed || owner == null || !LocalSessionMetadata.TryReadBody(body, true, out var space, out _, out var metadata)) return false;
            LocalLoginRpcEngine.RegisteredPeer host = null;
            try
            {
                reason = "local-session-owner-not-registered";
                if (registration == null || !registration.TryCopyRegisteredPeer(out host)) return false;
                foreach (Entry entry in entries)
                {
                    if (entry.Pending.ContainsKey(owner))
                    { reason = "local-session-owner-has-pending-join"; return false; }
                    if (!ReferenceEquals(entry.Owner, owner)) continue;
                    reason = "local-session-owner-registration-mismatch";
                    if (!entry.Host.Matches(host)) return false;
                    reason = "local-session-owner-already-hosting";
                    if (!body.SequenceEqual(entry.Body)) return false;
                    id = entry.Id;
                    reason = "local-session-create-replayed";
                    return true;
                }
                reason = "local-session-capacity-exhausted";
                if (entries.Count >= MaximumSessions || nextId == uint.MaxValue) return false;
                entries.Add(new(owner, nextId, body.ToArray(), space.ToArray(), metadata, host));
                RemovePreview(owner);
                metadata = null; host = null; // Registry now owns both.
                id = nextId++;
                reason = "local-session-record-created";
                return true;
            }
            finally { metadata?.Dispose(); host?.Dispose(); }
        }

        internal bool TryUpdate(object owner, ReadOnlySpan<byte> body, out string reason)
        {
            reason = "unsupported-update-arguments";
            if (closed || owner == null || !LocalSessionMetadata.TryReadBody(body, false, out var space, out uint id, out var patch)) return false;
            using (patch)
            {
                reason = "local-session-update-owner-or-space-mismatch";
                foreach (Entry entry in entries)
                {
                    if (entry.Id != id || !ReferenceEquals(entry.Owner, owner) || !space.SequenceEqual(entry.Space)) continue;
                    reason = "local-session-metadata-limit";
                    if (!entry.Metadata.TryMerge(patch, out var merged)) return false;
                    using var projection = Snapshot(entry, replacement: merged);
                    if (projection == null) { merged.Dispose(); return false; }
                    entry.Metadata.Dispose(); entry.Metadata = merged;
                    reason = "local-session-metadata-updated";
                    return true;
                }
                return false;
            }
        }

        // Hosts remove their record; pending clients remove only their own
        // reservation, never another transport's session or membership.
        internal bool TryLeave(object owner, ReadOnlySpan<byte> body, out string reason)
        {
            reason = "unsupported-leave-arguments";
            if (closed || owner == null || !LocalSessionMetadata.TryReadLeaveBody(body, out var space, out uint id)) return false;
            reason = "local-session-leave-owner-or-space-mismatch";
            for (int i = 0; i < entries.Count; ++i)
            {
                Entry entry = entries[i];
                if (entry.Id != id || !space.SequenceEqual(entry.Space)) continue;
                if (!ReferenceEquals(entry.Owner, owner))
                {
                    if (!entry.Pending.Remove(owner, out var pending)) continue;
                    pending.Dispose(); reason = "local-session-pending-member-left"; return true;
                }
                if (DisplayProbe && (previews.ContainsKey(owner) || previews.Count < MaximumSessions))
                {
                    RemovePreview(owner);
                    previews.Add(owner, new(entry.Id, entry.Space, entry.Metadata.Clone(), entry.Host.Clone()));
                }
                entry.Dispose(); entries.RemoveAt(i);
                reason = "local-session-record-left";
                return true;
            }
            return false;
        }

        // Owned snapshot for a future GetSession serializer; the caller disposes it.
        internal bool TryGetMetadata(object owner, uint id, out LocalSessionMetadata metadata)
        {
            metadata = null;
            if (closed) return false;
            foreach (Entry entry in entries)
                if (entry.Id == id && ReferenceEquals(entry.Owner, owner))
                {
                    metadata = entry.Metadata.Clone(); return true;
                }
            return false;
        }

        // Independent caller-owned projection; no raw identity or URL is logged.
        internal bool TryGetHost(object owner, uint id, out LocalLoginRpcEngine.RegisteredPeer host)
        {
            host = null;
            if (closed) return false;
            foreach (Entry entry in entries)
                if (entry.Id == id && ReferenceEquals(entry.Owner, owner))
                {
                    host = entry.Host.Clone(); return true;
                }
            return false;
        }

        internal void RemoveOwner(object owner)
        {
            RemovePreview(owner);
            foreach (Entry entry in entries)
                if (entry.Pending.Remove(owner, out var member)) member.Dispose();
            for (int i = entries.Count - 1; i >= 0; --i)
                if (ReferenceEquals(entries[i].Owner, owner))
                {
                    entries[i].Dispose();
                    entries.RemoveAt(i);
                }
        }

        public void Dispose()
        {
            if (closed) return;
            closed = true;
            foreach (Entry entry in entries) entry.Dispose();
            entries.Clear();
            foreach (var preview in previews.Values) preview.Dispose();
            previews.Clear();
        }

        private void RemovePreview(object owner)
        {
            if (owner != null && previews.Remove(owner, out var preview)) preview.Dispose();
        }

        internal bool TryCopyDisplaySnapshot(object owner, out DisplaySnapshot snapshot)
        {
            snapshot = null;
            if (closed || !DisplayProbe || owner == null || !previews.TryGetValue(owner, out var value)) return false;
            snapshot = new(value.Id, value.Space, value.Metadata.Clone(), value.Host.Clone());
            return true;
        }

        // Owned immutable projection, not a mutable registry entry. Previews and
        // live lookups are separate; retired previews cannot be fetched by ID.
        internal sealed class DisplaySnapshot(uint id, ReadOnlySpan<byte> space, LocalSessionMetadata metadata,
            LocalLoginRpcEngine.RegisteredPeer host) : IDisposable
        {
            internal uint Id { get; } = id;
            internal byte[] Space { get; } = space.ToArray();
            internal LocalSessionMetadata Metadata { get; } = metadata;
            internal LocalLoginRpcEngine.RegisteredPeer Host { get; } = host;
            internal List<byte[]> PendingProfiles { get; } = new();
            public void Dispose()
            {
                CryptographicOperations.ZeroMemory(Space); Metadata.Dispose(); Host.Dispose();
                foreach (var profile in PendingProfiles) CryptographicOperations.ZeroMemory(profile);
                PendingProfiles.Clear();
            }
        }

        private sealed class Entry(object owner, uint id, byte[] body, byte[] space, LocalSessionMetadata metadata, LocalLoginRpcEngine.RegisteredPeer host) : IDisposable
        {
            internal readonly object Owner = owner;
            internal readonly uint Id = id;
            internal readonly byte[] Body = body, Space = space;
            internal LocalSessionMetadata Metadata = metadata;
            internal readonly LocalLoginRpcEngine.RegisteredPeer Host = host;
            internal readonly Dictionary<object, PendingMember> Pending = new(ReferenceEqualityComparer.Instance);
            public void Dispose()
            {
                CryptographicOperations.ZeroMemory(Body); CryptographicOperations.ZeroMemory(Space);
                Metadata.Dispose(); Host.Dispose();
                foreach (var pending in Pending.Values) pending.Dispose();
                Pending.Clear();
            }
        }
    }
}
