using System.Buffers.Binary;
using System.Security.Cryptography;
using S7Patcher.Source;

internal static class ReliableResponseQueueChecks
{
    private static ushort Sequence(byte[] packet) => BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(8));
    internal static int Run()
    {
        if (!OperatingSystem.IsWindows()) { Console.WriteLine("SKIP: response fragmentation checks require Windows CNG."); return 0; }
        int passed = 0;
        void Check(bool value, string label) { if (!value) throw new Exception(label); passed++; }
        byte[] key = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        byte[] Encode(ushort seq, byte part, ReadOnlySpan<byte> bytes) =>
            PrudpDataPacketEncoder.Encode(0x31, 0x3a, 7, 0x12345678, seq, part, bytes, key);
        try
        {
            // Independently decrypt every fragment with native CNG and then use
            // the reliable receiver with reversed arrivals, including u16 wrap.
            foreach (int length in new[] { 0, 1, 946, 947, 948, 1894, 1895, 65536 })
            foreach (ushort initial in new ushort[] { 1, 65534 })
            {
                byte[] message = new byte[length]; new Random(length + initial).NextBytes(message);
                byte[] original = (byte[])message.Clone();
                using ReliableResponseQueue queue = new(initial);
                using ReliableMessageAssembler receiver = new(initial);
                Check(queue.TryEnqueue(message, Encode) && queue.Count == 1, "Bounded response rejected");
                Check(message.SequenceEqual(original), "Queue mutated plaintext");
                byte[] complete = null;
                int index = 0, total = Math.Max(1, (length + 946) / 947);
                while (queue.Count != 0)
                {
                    var batch = queue.TakeDue(100, out bool timedOut);
                    Check(!timedOut && batch.Count is > 0 and <= 2, "Send window stalled or exceeded bound");
                    foreach (byte[] packet in batch)
                    {
                        Check(Sequence(packet) == unchecked((ushort)(initial + index))
                            && packet[10] == (index + 1 == total ? 0 : index + 1) && packet.Length <= 991,
                            "Wrong fragment sequence/part/size");
                        index++;
                    }
                    foreach (byte[] packet in batch.Reverse())
                    {
                        ushort seq = Sequence(packet); byte part = packet[10];
                        byte[] plaintext = null;
                        var result = PrudpDataCryptoProbe.InspectBody(packet.AsSpan(11, packet.Length - 15), seq, key,
                            bytes => plaintext = bytes.ToArray());
                        Check(result.SequenceMatches == true && plaintext != null && plaintext.Length <= 947,
                            "Independent native per-fragment decryption failed");
                        Check(receiver.AddFragment(seq, part, plaintext) == ReliableEnqueueResult.Accepted, "Receiver rejected fragment");
                        CryptographicOperations.ZeroMemory(plaintext);
                        if (receiver.TryTakeMessage(out var assembled))
                        {
                            Check(complete == null, "One response became multiple messages"); complete = assembled;
                        }
                        Check(queue.TryAcknowledge(seq, part) && packet.All(b => b == 0), "ACK did not clear owned ciphertext");
                        Check(!queue.TryAcknowledge(seq, part), "Duplicate ACK accepted");
                    }
                }
                Check(index == total && queue.CompletedResponses == 1 && queue.OutstandingPackets == 0
                    && complete != null && complete.SequenceEqual(original), "Reassembled response differs or completion counted per packet");
                CryptographicOperations.ZeroMemory(complete);
                Check(queue.TakeDue(99999, out _).Count == 0, "ACKed response retransmitted");
            }
            // ACKing the later packet must not slide the window past a gap.
            using (ReliableResponseQueue queue = new())
            {
                byte[] large = new byte[4000]; new Random(9).NextBytes(large);
                Check(queue.TryEnqueue(large, Encode), "Gap setup failed");
                Check(!queue.TryAcknowledge(1, 1) && !queue.TryAcknowledge(3, 3), "Unsent fragment ACK accepted");
                var first = queue.TakeDue(0, out _); byte[] lost = first[0], later = first[1];
                byte[] stable = (byte[])lost.Clone();
                Check(!queue.TryAcknowledge(1, 0) && queue.TryAcknowledge(2, 2), "Part match guard failed");
                Check(queue.TakeDue(999, out _).Count == 0 && !queue.TryAcknowledge(3, 3), "Window advanced past missing first ACK");
                var retry = queue.TakeDue(1000, out _);
                Check(retry.Count == 1 && ReferenceEquals(retry[0], lost) && lost.SequenceEqual(stable), "Retry re-encrypted or included ACKed packet");
                Check(queue.TryAcknowledge(1, 1), "Lost packet ACK rejected");
                var next = queue.TakeDue(1000, out _);
                Check(next.Count == 2 && Sequence(next[0]) == 3 && Sequence(next[1]) == 4, "Window failed to advance through ACKed hole");
                Check(queue.Count == 1 && queue.CompletedResponses == 0, "Partial response counted complete");
                queue.Dispose();
                Check(next.All(p => p.All(b => b == 0)) && queue.Count == 0 && queue.OutstandingPackets == 0,
                    "Disposal retained ciphertext");
                Check(!queue.TryEnqueue([], Encode) && !queue.TryAcknowledge(3, 3) && queue.TakeDue(1001, out _).Count == 0,
                    "Disposed queue revived");
            }
            // A missing ACK expires both sent and not-yet-sent fragments atomically.
            using (ReliableResponseQueue queue = new())
            {
                List<byte[]> owned = new();
                byte[] Capture(ushort seq, byte part, ReadOnlySpan<byte> bytes)
                { var packet = Encode(seq, part, bytes); owned.Add(packet); return packet; }
                Check(queue.TryEnqueue(new byte[3000], Capture) && queue.TryEnqueue([1], Capture)
                    && !queue.TryEnqueue([2], Capture), "Logical response capacity not enforced");
                for (int attempt = 0; attempt < 4; ++attempt)
                    Check(queue.TakeDue(attempt * 1000, out bool expired).Count == 2 && !expired, "Retry schedule differs");
                Check(queue.TakeDue(4000, out bool timedOut).Count == 0 && timedOut
                    && owned.All(p => p.All(b => b == 0)) && queue.Count == 0, "Timeout returned invalidated references or retained unsent packets");
            }
            // Encode failure must not publish partial data or consume sequence IDs.
            using (ReliableResponseQueue queue = new(65535))
            {
                List<byte[]> owned = new(); int calls = 0;
                byte[] Fail(ushort seq, byte part, ReadOnlySpan<byte> bytes)
                {
                    if (++calls == 2) throw new InvalidOperationException("invented encoder failure");
                    var packet = Encode(seq, part, bytes); owned.Add(packet); return packet;
                }
                bool threw = false;
                try { queue.TryEnqueue(new byte[948], Fail); } catch (InvalidOperationException) { threw = true; }
                Check(threw && queue.Count == 0 && queue.OutstandingPackets == 0 && owned.Single().All(b => b == 0),
                    "Encoding failure partially published response");
                Check(!queue.TryEnqueue(new byte[65537], Fail) && calls == 2, "Oversize response encoded before rejection");
                Check(queue.TryEnqueue([3], Encode), "Queue unusable after failed encode");
                var valid = queue.TakeDue(0, out _).Single();
                Check(Sequence(valid) == 65535 && valid[10] == 0 && queue.TryAcknowledge(65535, 0), "Failed enqueue consumed sequence");
                Check(queue.TryEnqueue([4], Encode) && Sequence(queue.TakeDue(0, out _).Single()) == 0, "Response boundary did not wrap sequence");
            }
            return passed;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
}
