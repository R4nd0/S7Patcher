using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace S7Patcher.Source
{
    // Isolated plaintext reassembly after transport/context/decryption validation.
    // Not thread-safe. Caller supplies the known reliable position (including any
    // CONNECT/control consumption) and handles expiry by explicit Reset.
    internal sealed class ReliableMessageAssembler : IDisposable
    {
        internal const int SequenceWindow = 32;
        internal const int MaximumMessageLength = 65536;
        internal const int MaximumFragments = 256;
        private readonly Dictionary<ushort, Fragment> pending = new();
        private readonly byte[] assembly = new byte[MaximumMessageLength];
        private int queuedBytes, assemblyLength, fragmentCount;
        private byte expectedPart = 1;
        private bool discardUntilFinal, requiresReset, disposed;

        internal ReliableMessageAssembler(ushort initialExpectedSequence) => NextExpectedSequence = initialExpectedSequence;
        internal ushort NextExpectedSequence { get; private set; }
        internal int BufferedFragmentCount => pending.Count;
        internal int BufferedByteCount => queuedBytes + assemblyLength;
        internal int FragmentsInCurrentMessage => fragmentCount;
        internal bool RequiresReset => requiresReset;
        internal bool DiscardingUntilFinal => discardUntilFinal;
        internal ReliableDropReason LastDropReason { get; private set; }

        // Copies only an accepted fragment. Input remains caller-owned and is never
        // modified. The 32-slot window includes the current expected sequence.
        internal ReliableEnqueueResult AddFragment(ushort sequence, byte part, ReadOnlySpan<byte> plaintext)
        {
            ThrowIfDisposed();
            if (requiresReset) return ReliableEnqueueResult.RequiresReset;
            int distance = unchecked((ushort)(sequence - NextExpectedSequence));
            if (distance > 0x8000) return ReliableEnqueueResult.OldOrDuplicate;
            if (distance >= SequenceWindow) return ReliableEnqueueResult.OutsideWindow;
            if (pending.ContainsKey(sequence)) return ReliableEnqueueResult.OldOrDuplicate;
            // Bound aggregate stored plaintext too, including future messages queued
            // behind a gap. Overflow never guesses a new message/sequence boundary.
            if (plaintext.Length > MaximumMessageLength - BufferedByteCount)
            {
                ClearStorage(); requiresReset = true; LastDropReason = ReliableDropReason.BufferLimit;
                return ReliableEnqueueResult.BufferLimitRequiresReset;
            }
            pending.Add(sequence, new(part, plaintext.ToArray()));
            queuedBytes += plaintext.Length;
            return ReliableEnqueueResult.Accepted;
        }

        // Drains only consecutive reliable sequences, returns at most one message.
        // Caller owns a successful result and must zero it after use. Call repeatedly
        // after enqueueing to take additional already queued complete messages.
        internal bool TryTakeMessage(out byte[] message)
        {
            ThrowIfDisposed(); message = null;
            if (requiresReset) return false;
            while (pending.Remove(NextExpectedSequence, out Fragment fragment))
            {
                NextExpectedSequence = unchecked((ushort)(NextExpectedSequence + 1));
                queuedBytes -= fragment.Plaintext.Length;
                try
                {
                    if (discardUntilFinal)
                    {
                        if (fragment.Part == 0) { discardUntilFinal = false; ClearAssembly(); }
                        continue;
                    }
                    if (fragment.Part != 0 && fragment.Part != expectedPart)
                    {
                        DropMessage(ReliableDropReason.InvalidPart, true);
                        continue;
                    }
                    if (fragmentCount == MaximumFragments)
                    {
                        DropMessage(ReliableDropReason.FragmentLimit, fragment.Part != 0);
                        continue;
                    }
                    fragment.Plaintext.CopyTo(assembly, assemblyLength);
                    assemblyLength += fragment.Plaintext.Length;
                    fragmentCount++;
                    if (fragment.Part == 0)
                    {
                        message = assembly.AsSpan(0, assemblyLength).ToArray();
                        ClearAssembly();
                        return true;
                    }
                    expectedPart = expectedPart == 255 ? (byte)1 : (byte)(expectedPart + 1);
                }
                finally { CryptographicOperations.ZeroMemory(fragment.Plaintext); }
            }
            return false;
        }

        // Use for externally timed expiry or a new known transport position. No
        // clock, sequence inference or automatic reconnection policy lives here.
        internal void Reset(ushort expectedSequence)
        {
            ThrowIfDisposed(); ClearStorage(); NextExpectedSequence = expectedSequence;
            requiresReset = false; LastDropReason = ReliableDropReason.None;
        }

        private void DropMessage(ReliableDropReason reason, bool discard)
        {
            ClearAssembly(); discardUntilFinal = discard; LastDropReason = reason;
        }
        private void ClearAssembly()
        {
            CryptographicOperations.ZeroMemory(assembly);
            assemblyLength = 0; fragmentCount = 0; expectedPart = 1;
        }
        private void ClearStorage()
        {
            foreach (Fragment fragment in pending.Values) CryptographicOperations.ZeroMemory(fragment.Plaintext);
            pending.Clear(); queuedBytes = 0; ClearAssembly(); discardUntilFinal = false;
        }
        private void ThrowIfDisposed()
        {
            if (disposed) throw new ObjectDisposedException(nameof(ReliableMessageAssembler));
        }
        public void Dispose()
        {
            if (disposed) return;
            ClearStorage(); disposed = true;
        }
        private sealed class Fragment
        {
            internal Fragment(byte part, byte[] plaintext) { Part = part; Plaintext = plaintext; }
            internal byte Part { get; }
            internal byte[] Plaintext { get; }
        }
    }
    internal enum ReliableEnqueueResult { Accepted, OldOrDuplicate, OutsideWindow, BufferLimitRequiresReset, RequiresReset }
    internal enum ReliableDropReason { None, InvalidPart, FragmentLimit, BufferLimit }
}
