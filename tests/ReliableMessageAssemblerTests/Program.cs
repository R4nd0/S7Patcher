using System.Collections;
using System.Reflection;
using System.Security.Cryptography;
using S7Patcher.Source;

int passed = 0;
void Check(bool condition, string message) { if (!condition) throw new Exception(message); passed++; }
static byte[] AssemblyStorage(ReliableMessageAssembler value) => (byte[])typeof(ReliableMessageAssembler)
    .GetField("assembly", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(value)!;
static byte[][] QueuedStorage(ReliableMessageAssembler value)
{
    IDictionary queue = (IDictionary)typeof(ReliableMessageAssembler).GetField("pending", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(value)!;
    return queue.Values.Cast<object>().Select(item => (byte[])item.GetType()
        .GetProperty("Plaintext", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(item)!).ToArray();
}
void Empty(ReliableMessageAssembler value) => Check(!value.TryTakeMessage(out byte[] result) && result == null, "Message delivered across a gap or without final marker");
void Add(ReliableMessageAssembler value, ushort sequence, byte part, byte[] bytes) =>
    Check(value.AddFragment(sequence, part, bytes) == ReliableEnqueueResult.Accepted, "Expected fragment rejected");
void Message(ReliableMessageAssembler value, byte[] expected)
{
    Check(value.TryTakeMessage(out byte[] actual) && actual.SequenceEqual(expected), "Complete message differs");
    Check(AssemblyStorage(value).All(item => item == 0), "Assembly retained completed plaintext");
    CryptographicOperations.ZeroMemory(actual);
}
using (ReliableMessageAssembler value = new(12))
{
    byte[] caller = [1, 2, 3]; Add(value, 12, 0, caller);
    byte[] owned = QueuedStorage(value).Single(); caller[0] = 9;
    Message(value, [1, 2, 3]); Check(caller[0] == 9 && owned.All(item => item == 0), "Ownership copy or consumed fragment zeroing failed");
    Check(value.NextExpectedSequence == 13, "Explicit starting sequence ignored");
    Check(value.AddFragment(12, 0, [99]) == ReliableEnqueueResult.OldOrDuplicate, "Consumed retry delivered twice"); Empty(value);
    Add(value, 13, 0, []); Message(value, []);
}
using (ReliableMessageAssembler value = new(100))
{
    Add(value, 102, 0, [5, 6]); Add(value, 101, 2, [3, 4]); Empty(value);
    Check(value.AddFragment(101, 99, [9, 9]) == ReliableEnqueueResult.OldOrDuplicate, "Conflicting duplicate replaced first fragment");
    Add(value, 100, 1, [1, 2]); Message(value, [1, 2, 3, 4, 5, 6]); Empty(value);
    Check(value.NextExpectedSequence == 103 && value.BufferedByteCount == 0, "Ordered drain position or count incorrect");
    Add(value, 104, 0, [8]); Add(value, 103, 0, [7]); Message(value, [7]); Message(value, [8]);
}
using (ReliableMessageAssembler value = new(65535))
{
    Add(value, 1, 0, [3]); Add(value, 0, 2, [2]); Add(value, 65535, 1, [1]); Message(value, [1, 2, 3]);
    Check(value.NextExpectedSequence == 2, "u16 sequence wrap failed");
    Check(value.AddFragment(65535, 0, [9]) == ReliableEnqueueResult.OldOrDuplicate, "Old pre-wrap sequence accepted");
    value.Reset(0); Add(value, 0, 0, [4]); Message(value, [4]); // Known post-CONNECT 65535+1 position.
}
using (ReliableMessageAssembler value = new(10))
{
    Add(value, 41, 0, [1]);
    Check(value.AddFragment(42, 0, [2]) == ReliableEnqueueResult.OutsideWindow, "32-slot window exceeded");
    Check(value.AddFragment(unchecked((ushort)(10 + 0x8000)), 0, [2]) == ReliableEnqueueResult.OutsideWindow, "Ambiguous half-range sequence accepted");
    Check(value.AddFragment(9, 0, [2]) == ReliableEnqueueResult.OldOrDuplicate, "Older sequence accepted"); Empty(value);
    byte[] queued = QueuedStorage(value).Single(); value.Reset(77);
    Check(queued.All(item => item == 0) && value.BufferedFragmentCount == 0 && value.NextExpectedSequence == 77, "Expiry reset failed to zero queue/rebase explicit position");
    Add(value, 77, 1, [5]); Empty(value); value.Reset(80);
    Check(AssemblyStorage(value).All(item => item == 0) && value.BufferedByteCount == 0, "Expiry left partial message plaintext");
}
using (ReliableMessageAssembler value = new(1))
{
    Add(value, 1, 1, [1]); Empty(value); Add(value, 2, 3, [2]); Empty(value);
    Check(value.LastDropReason == ReliableDropReason.InvalidPart && value.DiscardingUntilFinal && value.BufferedByteCount == 0, "Unexpected part did not discard partial message");
    Add(value, 3, 0, [99]); Empty(value); // Orphan tail must never become a standalone message.
    Check(!value.DiscardingUntilFinal, "Final marker did not end discard state");
    Add(value, 4, 0, [4]); Message(value, [4]);
    Add(value, 5, 2, [5]); Empty(value); Add(value, 6, 1, [6]); Empty(value); Add(value, 7, 0, [7]); Empty(value);
    Add(value, 8, 1, [8]); Empty(value); // Missing final is retained until external expiry.
    Check(value.FragmentsInCurrentMessage == 1 && value.BufferedByteCount == 1, "Partial message completed without final");
}
using (ReliableMessageAssembler value = new(1))
{
    byte[] maximum = Enumerable.Repeat((byte)0x5a, ReliableMessageAssembler.MaximumMessageLength).ToArray();
    Add(value, 1, 0, maximum); Message(value, maximum);
    Add(value, 2, 1, [1]); Empty(value); Add(value, 4, 0, [4]); byte[] queued = QueuedStorage(value).Single();
    Check(value.AddFragment(3, 2, maximum) == ReliableEnqueueResult.BufferLimitRequiresReset, "Aggregate plaintext cap exceeded");
    Check(value.RequiresReset && value.BufferedByteCount == 0 && value.BufferedFragmentCount == 0
        && AssemblyStorage(value).All(item => item == 0) && queued.All(item => item == 0), "Overflow did not zero all owned storage");
    Check(value.AddFragment(3, 0, [3]) == ReliableEnqueueResult.RequiresReset, "Overflow guessed a new message boundary"); Empty(value);
    value.Reset(20); Add(value, 20, 0, [20]); Message(value, [20]);
    Check(value.AddFragment(21, 0, new byte[ReliableMessageAssembler.MaximumMessageLength + 1]) == ReliableEnqueueResult.BufferLimitRequiresReset, "Oversize single fragment accepted");
}
using (ReliableMessageAssembler value = new(1))
{
    for (int index = 1; index <= 255; index++) { Add(value, (ushort)index, (byte)index, [(byte)index]); Empty(value); }
    Add(value, 256, 0, []); Message(value, Enumerable.Range(1, 255).Select(item => (byte)item).ToArray());
    value.Reset(1);
    for (int index = 1; index <= 256; index++) { Add(value, (ushort)index, (byte)(((index - 1) % 255) + 1), []); Empty(value); }
    Check(value.FragmentsInCurrentMessage == 256 && value.LastDropReason == ReliableDropReason.None, "Nonzero part counter did not wrap 255 to1");
    Add(value, 257, 0, [1]); Empty(value);
    Check(value.LastDropReason == ReliableDropReason.FragmentLimit && !value.DiscardingUntilFinal, "257th fragment exceeded cap or final did not recover boundary");
    Add(value, 258, 0, [2]); Message(value, [2]);
}
ReliableMessageAssembler disposed = new(1);
Add(disposed, 1, 1, [1]); Empty(disposed); Add(disposed, 3, 0, [3]);
byte[] queuedBeforeDispose = QueuedStorage(disposed).Single(), assemblyBeforeDispose = AssemblyStorage(disposed);
disposed.Dispose(); disposed.Dispose();
Check(queuedBeforeDispose.All(item => item == 0) && assemblyBeforeDispose.All(item => item == 0), "Dispose left plaintext");
foreach (Action operation in new Action[] { () => disposed.AddFragment(1, 0, []), () => disposed.TryTakeMessage(out _), () => disposed.Reset(1) })
{
    try { operation(); throw new Exception("Disposed assembler accepted operation"); }
    catch (ObjectDisposedException) { passed++; }
}
// Shuffle all fragments inside one window; modular sequence, not arrival or part
// order, must decide concatenation. Seeded repeats exercise wrap and duplicates.
Random random = new(12345);
for (int trial = 0; trial < 100; trial++)
{
    ushort initial = (ushort)random.Next(65536);
    using ReliableMessageAssembler value = new(initial);
    int[] order = Enumerable.Range(0, 32).OrderBy(_ => random.Next()).ToArray();
    foreach (int index in order)
    {
        ushort sequence = unchecked((ushort)(initial + index));
        Add(value, sequence, index == 31 ? (byte)0 : (byte)(index + 1), [(byte)index]);
        Check(value.AddFragment(sequence, 0, [255]) == ReliableEnqueueResult.OldOrDuplicate, "Shuffled duplicate not suppressed");
    }
    Message(value, Enumerable.Range(0, 32).Select(item => (byte)item).ToArray()); Empty(value);
}
Console.WriteLine($"PASS: {passed} isolated reliable-assembly checks; ordering, gaps, duplicates, sequence/part wrap, limits, reset, ownership and plaintext zeroing. No runtime integration.");
