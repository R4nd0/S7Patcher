using System.Text;
using S7Patcher.Source;

internal static class LocalJoinFailureChecks
{
    internal const string NativeDescription = "Session:Session request refused (System error: 0) - No eresult string available.";
    internal static byte[] Body(uint sessionKind = 0, string text = "private-fixture-text", string space = "invented-space", uint id = 1)
    {
        using var stream = new MemoryStream(); using var writer = new BinaryWriter(stream);
        void Text(string value) { var bytes = Encoding.ASCII.GetBytes(value); writer.Write((ushort)(bytes.Length + 1)); writer.Write(bytes); writer.Write((byte)0); }
        writer.Write(0u); Text(space); writer.Write(sessionKind); writer.Write(id); Text(text);
        return stream.ToArray();
    }
    internal static byte[] Request(byte[] body = null) => LocalSessionCreationChecks.Request(
        method:"MatchmakingProtocol::ReportJoinFailure_V1", body:body ?? Body());

    internal static int Run()
    {
        int passed = 0;
        void Check(bool b, string label) { if (!b) throw new Exception(label); passed++; }
        byte[] body = Body();
        Check(LocalSessionMetadata.TryReadJoinFailureBody(body, out var space, out var id, out var kind, out var length)
            && space.SequenceEqual("invented-space"u8) && id == 1 && kind == 0 && length == 20, "Failure report shape");
        // Independently transcribed native call-chain layout, synthetic values only:
        // empty class map; qString "s"; kind 0; session ID 0x11223344; empty qString.
        byte[] nativeLayout = [0,0,0,0, 2,0,0x73,0, 0,0,0,0, 0x44,0x33,0x22,0x11, 1,0,0];
        Check(LocalSessionMetadata.TryReadJoinFailureBody(nativeLayout, out space, out id, out kind, out length)
            && space.SequenceEqual("s"u8) && id == 0x11223344 && kind == 0 && length == 0,
            "Native report field order: zero kind must not be treated as session ID");
        byte[] reversed = [..nativeLayout[..8], 0x44,0x33,0x22,0x11, 0,0,0,0, 1,0,0];
        Check(!LocalSessionMetadata.TryReadJoinFailureBody(reversed, out _, out _, out _, out _),
            "Reversed native report fields accepted");
        byte[] nullText = [..nativeLayout[..16], 0,0];
        Check(LocalSessionMetadata.TryReadJoinFailureBody(nullText, out _, out _, out _, out length) && length == 0,
            "Native null qString rejected");
        byte[] description = Encoding.ASCII.GetBytes(NativeDescription);
        Check(LocalJoinFailureDescription.Classify(description) == "session-request-refused", "Native result formatter classification");
        Check(LocalSessionMetadata.TryReadJoinFailureBody(Body(text:NativeDescription), out _, out _, out _, out _, out var category)
            && category == "session-request-refused", "Report description not classified");
        foreach (string number in new[]{"-2147483648", "4294967295"})
            Check(LocalJoinFailureDescription.Classify(Encoding.ASCII.GetBytes(NativeDescription.Replace("error: 0", "error: " + number)))
                == "session-request-refused", "System error boundary changes classification");
        for (int i=0; i<description.Length; i++)
            Check(LocalJoinFailureDescription.Classify(description.AsSpan(0,i)) == "unclassified", "Truncated description classified");
        foreach (string altered in new[]{NativeDescription + "secret", "secret" + NativeDescription,
            NativeDescription.Replace("Session:Session", "private-id:Session"),
            NativeDescription.Replace("request refused", "request refused private-id"),
            NativeDescription.Replace("error: 0", "error: 4294967296"),
            NativeDescription.Replace("error: 0", "error: -2147483649"),
            NativeDescription.Replace("error: 0", "error: +0"),
            NativeDescription.Replace("error: 0", "error: secret"),
            NativeDescription.Replace("error: 0", "error: 0\nsecret"), new string('x',4097)})
            Check(LocalJoinFailureDescription.Classify(Encoding.ASCII.GetBytes(altered)) == "unclassified", "Untrusted description classified");
        for (int i=0;i<body.Length;i++) Check(!LocalSessionMetadata.TryReadJoinFailureBody(body[..i], out _, out _, out _, out _), "Truncated failure accepted");
        foreach (var bad in new byte[][] { [..body, 0], [1,0,0,0,..body[4..]], Body(id:0), Body(id:uint.MaxValue), Body(text:new string('x',4097)), Body(space:new string('x',1025)) })
            Check(!LocalSessionMetadata.TryReadJoinFailureBody(bad, out _, out _, out _, out _), "Invalid failure body accepted");
        foreach (uint value in new uint[]{0,1,uint.MaxValue})
            Check(LocalSessionMetadata.TryReadJoinFailureBody(Body(value, ""), out _, out _, out var result, out var empty)
                && result == value && empty == 0, "Report kind bits or empty text changed");
        using var host = RegisteredHostChecks.CreateRegistered(); using var guest = RegisteredHostChecks.CreateRegistered();
        using var registry = new LocalSessionRegistry(catalogueProbe:true);
        object owner = new(), visitor = new();
        Check(registry.TryCreate(owner, host, LocalSessionCatalogueChecks.PublicBody(), out _, out _), "Failure fixture create");
        Check(!registry.TryObserveJoinFailure(visitor, guest, Request(), out _, out _, out _), "Unreserved failure accepted");
        Check(LocalSessionJoinCodec.TryReply(LocalSessionJoinChecks.Request(), registry, visitor, guest, out _, out _), "Failure fixture join");
        Check(registry.TryObserveJoinFailure(visitor, guest, Request(), out kind, out length, out var reason)
            && kind == 0 && length == 20 && reason == "local-join-failure-observed", "Own pending report rejected");
        Check(!registry.TryObserveJoinFailure(new object(), guest, Request(Body(text:NativeDescription)), out _, out _, out _, out category)
            && category == null, "Foreign report leaked classification");
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
