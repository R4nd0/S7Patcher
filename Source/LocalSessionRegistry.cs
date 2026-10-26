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

        internal bool TryCreate(object owner, ReadOnlySpan<byte> body, out uint id, out string reason)
        {
            id = 0;
            reason = "unsupported-create-arguments";
            if (closed || owner == null || !LocalSessionCreationCodec.ValidBody(body)) return false;
            foreach (Entry entry in entries)
            {
                if (!ReferenceEquals(entry.Owner, owner)) continue;
                reason = "local-session-owner-already-hosting";
                if (!body.SequenceEqual(entry.Body)) return false;
                id = entry.Id;
                reason = "local-session-create-replayed";
                return true;
            }
            reason = "local-session-capacity-exhausted";
            if (entries.Count >= MaximumSessions || nextId == uint.MaxValue) return false;
            entries.Add(new(owner, nextId, body.ToArray()));
            id = nextId++;
            reason = "local-session-record-created";
            return true;
        }

        internal void RemoveOwner(object owner)
        {
            for (int i = entries.Count - 1; i >= 0; --i)
                if (ReferenceEquals(entries[i].Owner, owner))
                {
                    CryptographicOperations.ZeroMemory(entries[i].Body);
                    entries.RemoveAt(i);
                }
        }

        public void Dispose()
        {
            if (closed) return;
            closed = true;
            foreach (Entry entry in entries) CryptographicOperations.ZeroMemory(entry.Body);
            entries.Clear();
        }

        private sealed record Entry(object Owner, uint Id, byte[] Body);
    }
}
