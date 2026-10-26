using System.Buffers.Binary;
using S7Patcher.Source;

internal static class LocalSessionLeaveChecks
{
    private static byte[] Ddl(string text) => LocalSessionSearchChecks.Ddl(text);
    internal static byte[] Body(uint id = 1, string space = "invented-space", byte flag = 0, string tail = "")
    {
        byte[] number = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(number, id);
        return [0, 0, 0, 0, .. Ddl(space), .. number, flag, .. Ddl(tail)];
    }
    internal static byte[] Request(uint callId = 0x12345678, byte[] body = null) =>
        LocalSessionCreationChecks.Request(callId, body ?? Body(), "MatchmakingProtocol::LeaveSession_V1");
    internal static byte[] Response(uint callId = 0x12345678)
    {
        byte[] result = [0, 0, 0, 0, .. Ddl("MatchmakingProtocol"), 0, 1, 0, 0, 0, 0,
            .. Ddl("MatchmakingProtocol::LeaveSession_V1*")];
        BinaryPrimitives.WriteUInt32LittleEndian(result, (uint)(result.Length - 4));
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(28), callId);
        return result;
    }
    internal static int Run()
    {
        using LocalLoginRpcEngine registration = RegisteredHostChecks.CreateRegistered();
        int passed = 0;
        void Check(bool value, string label) { if (!value) throw new Exception(label); passed++; }
        using LocalSessionRegistry registry = new(); object owner = new(), other = new();
        Check(registry.TryCreate(owner, registration, LocalSessionCreationChecks.Body(), out _, out _), "Leave setup failed");
        Check(registry.TryCreate(other, registration, LocalSessionCreationChecks.Body(), out _, out _), "Other owner setup failed");
        void Reject(byte[] request, object requester = null)
        {
            Check(!LocalSessionLeaveCodec.TryReply(request, registry, requester ?? owner, out var response, out _)
                && response == null && registry.Count == 2, "Invalid leave accepted or mutated registry");
        }
        byte[] body = Body(), message = Request();
        for (int i = 0; i < body.Length; ++i) Reject(Request(body: body[..i]));
        for (int i = 0; i < message.Length - body.Length; ++i)
        {
            byte[] partial = message[..i];
            if (i >= 4) BinaryPrimitives.WriteUInt32LittleEndian(partial, (uint)(i - 4));
            Reject(partial);
        }
        Reject(Request(body: [.. body, 0])); Reject(Request(body: Body(id: 0)));
        Reject(Request(body: Body(id: uint.MaxValue))); Reject(Request(body: Body(id: 2)));
        Reject(Request(body: Body(space: "other-space"))); Reject(Request(), other);
        Reject(Request(body: Body(flag: 2))); Reject(Request(body: Body(tail: new string('x', 65500))));
        byte[] wrong = (byte[])body.Clone(); wrong[0] = 1; Reject(Request(body: wrong));
        wrong = (byte[])body.Clone(); wrong[^1] = 1; Reject(Request(body: wrong));
        Reject(LocalSessionUpdateChecks.Request()); Reject(new byte[65537]);
        Random random = new(20261026);
        for (int i = 0; i < 100; ++i)
        {
            byte[] malformed = new byte[random.Next(0, 200)]; random.NextBytes(malformed); Reject(Request(body: malformed));
        }
        Check(LocalSessionLeaveCodec.TryReply(message, registry, owner, out var reply, out var reason)
            && reply.SequenceEqual(Response()) && reason == "local-session-record-left" && registry.Count == 1,
            "Leave response or removal differs");
        Check(!registry.TryGetMetadata(owner, 1, out _), "Leave retained metadata");
        Check(registry.TryGetMetadata(other, 2, out var remaining), "Leave affected other owner");
        remaining.Dispose();
        Check(!LocalSessionLeaveCodec.TryReply(message, registry, owner, out _, out _), "Nonexistent record accepted");
        Check(registry.TryCreate(owner, registration, LocalSessionCreationChecks.Body(), out uint next, out _) && next == 3,
            "Leave did not free owner for recreation");
        Check(!LocalSessionLeaveCodec.TryReply(message, registry, owner, out _, out _) && registry.Count == 2,
            "Stale leave removed newly created record");
        foreach (uint callId in new uint[] { 0, uint.MaxValue })
        {
            using LocalSessionRegistry fresh = new();
            Check(fresh.TryCreate(owner, registration, LocalSessionCreationChecks.Body(), out _, out _), "Fresh setup failed");
            Check(LocalSessionLeaveCodec.TryReply(Request(callId, Body(flag: 1, tail: "invented-opaque")), fresh, owner, out reply, out _)
                && reply.SequenceEqual(Response(callId)) && fresh.Count == 0, "Void leave reply/call ID mismatch");
        }
        registry.Dispose();
        Check(!registry.TryLeave(owner, Body(id: 3), out _), "Disposed registry accepted leave");
        return passed;
    }
}
