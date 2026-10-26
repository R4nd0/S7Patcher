#nullable enable
using System.Buffers.Binary;
using System.Text;
using S7Patcher.Source;

internal static class LocalSessionSearchChecks
{
    internal static byte[] Ddl(string value)
    {
        byte[] result = new byte[value.Length + 3];
        BinaryPrimitives.WriteUInt16LittleEndian(result, (ushort)(value.Length + 1));
        Encoding.ASCII.GetBytes(value, result.AsSpan(2)); return result;
    }
    internal static byte[] Body(byte[]? filters = null, uint count = 0)
    {
        byte[] number = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(number, count);
        return [2, 0, 0, 0, .. Ddl("MatchmakingSession"), 1, 0,
            .. Ddl("MatchmakingSessionMember"), 1, 0, .. Ddl("invented-space"),
            .. Ddl("invented-session-name"), .. number, .. (filters ?? []), 20, 0, 0, 0];
    }
    internal static byte[] Request(uint callId = 0x12345678, byte[]? body = null)
    {
        byte[] id = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(id, callId);
        byte[] message = [0, 0, 0, 0, .. Ddl("MatchmakingProtocol"), 1, .. id,
            .. Ddl("MatchmakingProtocol::SearchSessions_V1"), .. (body ?? Body())];
        BinaryPrimitives.WriteUInt32LittleEndian(message, (uint)(message.Length - 4)); return message;
    }
    internal static byte[] EmptyResponse(uint callId = 0x12345678)
    {
        // Fixed native layout: protocol, response/success, call ID, literal '*'
        // method suffix, u32 list count 0, u32 map count 0.
        byte[] expected = Convert.FromHexString("4e00000014004d617463686d616b696e6750726f746f636f6c0000017856341228004d617463686d616b696e6750726f746f636f6c3a3a53656172636853657373696f6e735f56312a000000000000000000");
        BinaryPrimitives.WriteUInt32LittleEndian(expected.AsSpan(28), callId); return expected;
    }
    internal static int Run()
    {
        int passed = 0;
        void Check(bool value, string label) { if (!value) throw new Exception(label); passed++; }
        void Reject(byte[] message)
        {
            Check(!LocalSessionSearchCodec.TryReply(message, out var response, out var reason)
                && response == null && reason is "unsupported-search-header" or "unsupported-search-arguments", "Malformed search accepted");
        }
        byte[] original = Request(), snapshot = (byte[])original.Clone();
        foreach (uint id in new uint[] { 0, 0x12345678, uint.MaxValue })
            Check(LocalSessionSearchCodec.TryReply(Request(id), out var reply, out var reason)
                && reply.SequenceEqual(EmptyResponse(id)) && reason == "local-empty-session-search-response-created", "Empty response differs from native vector");
        Check(LocalSessionSearchCodec.TryReply(original, out _, out _) && original.SequenceEqual(snapshot), "Search input mutated");
        for (int i = 0; i < original.Length; i++)
        {
            byte[] truncated = original[..i];
            if (i >= 4) BinaryPrimitives.WriteUInt32LittleEndian(truncated, (uint)(i - 4));
            Reject(truncated);
        }
        Reject(Request(body: [.. Body(), 0]));
        Reject(new byte[65537]);
        foreach (byte tag in Enumerable.Range(0, 8).Select(i => (byte)i))
        {
            byte[] value = tag == 4 ? Ddl("opaque-filter") : new byte[tag switch { 0 => 0, 3 => 1, 7 => 16, _ => 8 }];
            Check(LocalSessionSearchCodec.TryReply(Request(body: Body([.. Ddl("key"), tag, .. value], 1)), out var reply, out _)
                && reply.SequenceEqual(EmptyResponse()), "Supported variant shape rejected");
        }
        Reject(Request(body: Body([.. Ddl("key"), 8], 1)));
        Reject(Request(body: Body(count: 65)));
        byte[] wrong = Body(); wrong[0] = 1; Reject(Request(body: wrong));
        wrong = Body(); wrong[4] = 0; Reject(Request(body: wrong));
        wrong = Body(); wrong[6] = (byte)'X'; Reject(Request(body: wrong));
        wrong = Body(); wrong[4 + Ddl("MatchmakingSession").Length] = 2; Reject(Request(body: wrong));
        wrong = Request(); wrong[6] = (byte)'X'; Reject(wrong);
        wrong = Request(); wrong[26] = 0; Reject(wrong);
        Random random = new(20261026);
        for (int i = 0; i < 1000; i++)
        {
            byte[] body = new byte[random.Next(0, 400)]; random.NextBytes(body); Reject(Request(body: body));
        }
        return passed;
    }
}
