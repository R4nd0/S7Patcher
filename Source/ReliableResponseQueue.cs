using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace S7Patcher.Source
{
    // Single UDP-loop ownership. This queue retains ciphertext only. Its two-slot
    // sequence window cannot advance past a missing ACK, even if later ACKs arrive.
    internal sealed class ReliableResponseQueue : IDisposable
    {
        internal const int MaximumResponses = 2;
        internal const int WindowSize = 2;
        internal const int MaximumResponseLength = 65536;
        internal const int RetryMilliseconds = 1000;
        internal const int MaximumTransmissions = 4;
        internal delegate byte[] EncodeFragment(ushort sequence, byte part, ReadOnlySpan<byte> plaintext);
        private readonly LinkedList<Pending> packets = new();
        private readonly Dictionary<ushort, Pending> outstanding = new();
        private ushort nextSequence;
        private bool closed;
        internal int Count { get; private set; }
        internal int CompletedResponses { get; private set; }
        internal int OutstandingPackets => outstanding.Count;
        internal ReliableResponseQueue(ushort initialSequence = 1) => nextSequence = initialSequence;

        // Encode the entire response before publishing it or consuming sequence
        // numbers. Caller owns and clears plaintext. Failure leaves the queue intact.
        internal bool TryEnqueue(ReadOnlySpan<byte> response, EncodeFragment encode)
        {
            if (closed || Count >= MaximumResponses || response.Length > MaximumResponseLength) return false;
            ArgumentNullException.ThrowIfNull(encode);
            int count = Math.Max(1, (response.Length + PrudpDataPacketEncoder.PlaintextLimit - 1) / PrudpDataPacketEncoder.PlaintextLimit);
            List<Pending> encoded = new(count);
            Group group = new(count);
            ushort sequence = nextSequence;
            try
            {
                for (int index = 0; index < count; ++index)
                {
                    int start = index * PrudpDataPacketEncoder.PlaintextLimit;
                    int length = Math.Min(PrudpDataPacketEncoder.PlaintextLimit, response.Length - start);
                    byte part = index + 1 == count ? (byte)0 : (byte)(index + 1);
                    byte[] packet = encode(sequence, part, response.Slice(start, length));
                    if (packet == null) throw new InvalidOperationException("Fragment encoder returned no packet");
                    encoded.Add(new(sequence, part, packet, group));
                    sequence = unchecked((ushort)(sequence + 1));
                }
            }
            catch
            {
                foreach (Pending item in encoded) CryptographicOperations.ZeroMemory(item.Packet);
                throw;
            }
            foreach (Pending item in encoded)
            {
                packets.AddLast(item);
                outstanding.Add(item.Sequence, item);
            }
            nextSequence = sequence; Count++;
            return true;
        }

        // Transport validates checksum/peer/session/cookie/empty ACK before this.
        // Native ACKs echo PartNumber; reject guessed/unsent or mismatched parts.
        internal bool TryAcknowledge(ushort sequence, byte part)
        {
            if (closed || !outstanding.TryGetValue(sequence, out Pending item)
                || item.Transmissions == 0 || item.Part != part) return false;
            outstanding.Remove(sequence);
            CryptographicOperations.ZeroMemory(item.Packet);
            item.Acknowledged = true;
            if (--item.Response.Remaining == 0) { Count--; CompletedResponses++; }
            while (packets.First?.Value.Acknowledged == true) packets.RemoveFirst();
            return true;
        }

        internal IReadOnlyList<byte[]> TakeDue(long now, out bool timedOut)
        {
            List<byte[]> due = new();
            timedOut = false;
            if (closed) return due;
            // Check all expiry before handing out any references which Dispose
            // would otherwise zero underneath the caller.
            foreach (Pending item in outstanding.Values)
                if (item.Transmissions >= MaximumTransmissions && now >= item.NextSend)
                { timedOut = true; Dispose(); return due; }
            var node = packets.First;
            for (int slot = 0; slot < WindowSize && node != null; ++slot, node = node.Next)
            {
                Pending item = node.Value;
                if (item.Acknowledged || (item.Transmissions != 0 && now < item.NextSend)) continue;
                item.Transmissions++;
                item.NextSend = now + RetryMilliseconds;
                due.Add(item.Packet);
            }
            return due;
        }

        public void Dispose()
        {
            if (closed) return;
            closed = true;
            foreach (Pending item in packets) CryptographicOperations.ZeroMemory(item.Packet);
            packets.Clear(); outstanding.Clear(); Count = 0;
        }
        private sealed class Group(int remaining) { internal int Remaining = remaining; }
        private sealed class Pending(ushort sequence, byte part, byte[] packet, Group response)
        {
            internal readonly ushort Sequence = sequence;
            internal readonly byte Part = part;
            internal readonly byte[] Packet = packet;
            internal readonly Group Response = response;
            internal bool Acknowledged;
            internal int Transmissions;
            internal long NextSend;
        }
    }
}
