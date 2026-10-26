using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace S7Patcher.Source
{
    // Run-local records only. Called by the single UDP processing loop. Ownership
    // is the registered transport session, never a claimed identity from a body.
    internal sealed class LocalSessionRegistry : IDisposable
    {
        internal const int MaximumSessions = 8;
        private readonly List<Entry> entries = new();
        private uint nextId = 1;
        private bool closed;
        internal int Count => entries.Count;

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
                    entry.Metadata.Dispose(); entry.Metadata = merged;
                    reason = "local-session-metadata-updated";
                    return true;
                }
                return false;
            }
        }

        // Host-only prototype: no joined clients exist yet. Never remove another
        // transport's record using a claimed ID, flag or trailing string.
        internal bool TryLeave(object owner, ReadOnlySpan<byte> body, out string reason)
        {
            reason = "unsupported-leave-arguments";
            if (closed || owner == null || !LocalSessionMetadata.TryReadLeaveBody(body, out var space, out uint id)) return false;
            reason = "local-session-leave-owner-or-space-mismatch";
            for (int i = 0; i < entries.Count; ++i)
            {
                Entry entry = entries[i];
                if (entry.Id != id || !ReferenceEquals(entry.Owner, owner) || !space.SequenceEqual(entry.Space)) continue;
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
        }

        private sealed class Entry(object owner, uint id, byte[] body, byte[] space, LocalSessionMetadata metadata, LocalLoginRpcEngine.RegisteredPeer host) : IDisposable
        {
            internal readonly object Owner = owner;
            internal readonly uint Id = id;
            internal readonly byte[] Body = body, Space = space;
            internal LocalSessionMetadata Metadata = metadata;
            internal readonly LocalLoginRpcEngine.RegisteredPeer Host = host;
            public void Dispose()
            {
                CryptographicOperations.ZeroMemory(Body); CryptographicOperations.ZeroMemory(Space);
                Metadata.Dispose(); Host.Dispose();
            }
        }
    }
}
