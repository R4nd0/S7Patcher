#nullable enable
using System.Buffers.Binary;
using S7Patcher.Source;

internal static class LocalSessionCreationChecks
{
    private static byte[] Ddl(string text) => LocalSessionSearchChecks.Ddl(text);
    internal static byte[] Body(byte[]? variant = null, byte flag = 1)
    {
        // All identifiers and fields are invented; two maps exercise both Variant paths.
        byte[] value = variant ?? [4, .. Ddl("invented-value")];
        return [0, 0, 0, 0, .. Ddl("invented-space"), 1, 0, 0, 0, .. Ddl("attribute"), .. value,
            .. Ddl("invented-name"), 1, 0, 0, 0, .. Enumerable.Repeat((byte)0x57, 16),
            4, 0, 0, 0, 1, 0, 0, 0, .. Ddl("members"), 1, 0, 0, 0, .. new byte[16], .. value, flag];
    }
    internal static byte[] Request(uint callId = 0x12345678, byte[]? body = null,
        string method = "MatchmakingProtocol::CreateSession_V1")
    {
        byte[] id = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(id, callId);
        byte[] message = [0, 0, 0, 0, .. Ddl("MatchmakingProtocol"), 1, .. id, .. Ddl(method), .. (body ?? Body())];
        BinaryPrimitives.WriteUInt32LittleEndian(message, (uint)(message.Length - 4));
        return message;
    }
    internal static byte[] Response(uint callId = 0x12345678, uint sessionId = 1)
    {
        // Independently specified response envelope: response=0, success=1,
        // same opaque call ID, method '*' suffix, exactly one u32 output.
        byte[] result = [0, 0, 0, 0, .. Ddl("MatchmakingProtocol"), 0, 1, 0, 0, 0, 0,
            .. Ddl("MatchmakingProtocol::CreateSession_V1*"), 0, 0, 0, 0];
        BinaryPrimitives.WriteUInt32LittleEndian(result, (uint)(result.Length - 4));
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(28), callId);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(result.Length - 4), sessionId);
        return result;
    }
    internal static int Run()
    {
        int passed = 0;
        void Check(bool value, string label) { if (!value) throw new Exception(label); passed++; }
        object owner = new();
        using LocalSessionRegistry registry = new();
        byte[] body = Body(), original = (byte[])body.Clone();
        void Reject(byte[] request)
        {
            int count = registry.Count;
            Check(!LocalSessionCreationCodec.TryReply(request, registry, owner, out var response, out _)
                && response == null && registry.Count == count, "Malformed create mutated registry or replied");
        }
        for (int i = 0; i < body.Length; ++i) Reject(Request(body: body[..i]));
        byte[] envelope = Request();
        for (int i = 0; i < envelope.Length - body.Length; ++i)
        {
            byte[] truncated = envelope[..i];
            if (i >= 4) BinaryPrimitives.WriteUInt32LittleEndian(truncated, (uint)(i - 4));
            Reject(truncated);
        }
        Reject(Request(body: [.. body, 0]));
        Reject(Request(body: Body(flag: 2)));
        Reject(Request(body: Body([8])));
        Reject(Request(method: "MatchmakingProtocol::CreateSession2_V1"));
        Reject(LocalSessionSearchChecks.Request());
        Reject(new byte[65537]);
        byte[] wrong = (byte[])body.Clone(); wrong[0] = 1; Reject(Request(body: wrong));
        wrong = (byte[])body.Clone(); wrong[4] = 0xff; wrong[5] = 0xff; Reject(Request(body: wrong));
        wrong = (byte[])body.Clone(); wrong[4 + Ddl("invented-space").Length] = 65; Reject(Request(body: wrong));
        wrong = (byte[])body.Clone(); wrong[4 + Ddl("invented-space").Length - 1] = 1; Reject(Request(body: wrong));
        for (byte tag = 0; tag <= 7; ++tag)
        {
            byte[] value = tag == 4 ? Ddl("opaque") : new byte[tag switch { 0 => 0, 3 => 1, 7 => 16, _ => 8 }];
            Check(LocalSessionCreationCodec.ValidBody(Body([tag, .. value])), "Supported Variant rejected");
        }
        byte[] minimal = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        Check(LocalSessionCreationCodec.ValidBody(minimal), "Native null strings/empty maps rejected");
        foreach (int offset in new[] { 6, 12, 20 })
        {
            wrong = (byte[])minimal.Clone(); BinaryPrimitives.WriteUInt32LittleEndian(wrong.AsSpan(offset), uint.MaxValue);
            Reject(Request(body: wrong));
        }
        Random random = new(20261026);
        for (int i = 0; i < 300; ++i)
        {
            byte[] randomBody = new byte[random.Next(0, 400)]; random.NextBytes(randomBody);
            Reject(Request(body: randomBody));
        }
        Check(LocalSessionCreationCodec.TryReply(Request(body: body), registry, owner, out var created, out var reason)
            && reason == "local-session-record-created" && created.SequenceEqual(Response()) && registry.Count == 1,
            "Create did not allocate the exact native response");
        Check(body.SequenceEqual(original), "Input body mutated");
        body[6] ^= 1; // Registry must own a copy, not retain the caller's buffer.
        Check(LocalSessionCreationCodec.TryReply(Request(uint.MaxValue, original), registry, owner, out var replay, out reason)
            && replay.SequenceEqual(Response(uint.MaxValue)) && reason == "local-session-create-replayed" && registry.Count == 1,
            "Application retry duplicated record or used stale call ID");
        Reject(Request(body: Body(flag: 0)));
        List<object> owners = [owner];
        for (uint i = 2; i <= LocalSessionRegistry.MaximumSessions; ++i)
        {
            object next = new(); owners.Add(next);
            Check(LocalSessionCreationCodec.TryReply(Request(), registry, next, out var response, out _)
                && response.SequenceEqual(Response(sessionId: i)), "Independent owners collided");
        }
        Check(!registry.TryCreate(new(), original, out _, out reason) && reason == "local-session-capacity-exhausted",
            "Registry capacity not enforced");
        Check(registry.TryCreate(owner, original, out uint same, out _) && same == 1, "Retry failed at capacity");
        registry.RemoveOwner(new()); Check(registry.Count == 8, "Unrelated owner removed records");
        registry.RemoveOwner(owner); Check(registry.Count == 7, "Owner record not removed");
        Check(registry.TryCreate(new(), original, out uint replacement, out _) && replacement == 9, "Capacity not released or ID reused");
        registry.Dispose(); registry.Dispose();
        Check(registry.Count == 0 && !registry.TryCreate(owner, original, out _, out _), "Disposed registry revived");
        return passed;
    }
}
