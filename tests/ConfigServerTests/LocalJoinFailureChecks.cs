using System.Text;
using S7Patcher.Source;

internal static class LocalJoinFailureChecks
{
    internal static byte[] Body(uint code = 0x80000001, string text = "private-fixture-text", string space = "invented-space", uint id = 1)
    {
        using var stream = new MemoryStream(); using var writer = new BinaryWriter(stream);
        void Text(string value) { var bytes = Encoding.ASCII.GetBytes(value); writer.Write((ushort)(bytes.Length + 1)); writer.Write(bytes); writer.Write((byte)0); }
        writer.Write(0u); Text(space); writer.Write(id); writer.Write(code); Text(text);
        return stream.ToArray();
    }
    internal static byte[] Request(byte[] body = null) => LocalSessionCreationChecks.Request(
        method:"MatchmakingProtocol::ReportJoinFailure_V1", body:body ?? Body());

    internal static int Run()
    {
        int passed = 0;
        void Check(bool b, string label) { if (!b) throw new Exception(label); passed++; }
        byte[] body = Body();
        Check(LocalSessionMetadata.TryReadJoinFailureBody(body, out var space, out var id, out var code, out var length)
            && space.SequenceEqual("invented-space"u8) && id == 1 && code == 0x80000001 && length == 20, "Failure report shape");
        for (int i=0;i<body.Length;i++) Check(!LocalSessionMetadata.TryReadJoinFailureBody(body[..i], out _, out _, out _, out _), "Truncated failure accepted");
        foreach (var bad in new byte[][] { [..body, 0], [1,0,0,0,..body[4..]], Body(id:0), Body(id:uint.MaxValue), Body(text:new string('x',4097)), Body(space:new string('x',1025)) })
            Check(!LocalSessionMetadata.TryReadJoinFailureBody(bad, out _, out _, out _, out _), "Invalid failure body accepted");
        foreach (uint value in new uint[]{0,1,uint.MaxValue})
            Check(LocalSessionMetadata.TryReadJoinFailureBody(Body(value, ""), out _, out _, out var result, out var empty)
                && result == value && empty == 0, "Failure code bits or empty text changed");
        using var host = RegisteredHostChecks.CreateRegistered(); using var guest = RegisteredHostChecks.CreateRegistered();
        using var registry = new LocalSessionRegistry(catalogueProbe:true);
        object owner = new(), visitor = new();
        Check(registry.TryCreate(owner, host, LocalSessionCatalogueChecks.PublicBody(), out _, out _), "Failure fixture create");
        Check(!registry.TryObserveJoinFailure(visitor, guest, Request(), out _, out _, out _), "Unreserved failure accepted");
        Check(LocalSessionJoinCodec.TryReply(LocalSessionJoinChecks.Request(), registry, visitor, guest, out _, out _), "Failure fixture join");
        Check(registry.TryObserveJoinFailure(visitor, guest, Request(), out code, out length, out var reason)
            && code == 0x80000001 && length == 20 && reason == "local-join-failure-observed", "Own pending report rejected");
        foreach (var request in new[] { Request(Body(space:"other")), Request(Body(id:2)), LocalSessionJoinChecks.Request() })
            Check(!registry.TryObserveJoinFailure(visitor, guest, request, out _, out _, out _), "Wrong report scope accepted");
        Check(!registry.TryObserveJoinFailure(new object(), guest, Request(), out _, out _, out _), "Foreign transport accepted");
        Check(!registry.TryObserveJoinFailure(visitor, host, Request(), out _, out _, out _), "Foreign registration accepted");
        Check(!registry.TryObserveJoinFailure(visitor, null, Request(), out _, out _, out _), "Unregistered report accepted");
        Check(registry.TryCopyLiveSession(visitor, "invented-space"u8, 1, out var snapshot), "Observation removed session");
        using(snapshot) Check(snapshot.PendingProfiles.Count == 1, "Diagnostic changed membership");
        return passed;
    }
}
