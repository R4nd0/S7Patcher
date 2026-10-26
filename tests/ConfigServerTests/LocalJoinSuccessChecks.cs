using System.Buffers.Binary;
using S7Patcher.Source;

internal static class LocalJoinSuccessChecks
{
    internal static byte[] Body(uint kind = 0, uint id = 1, string space = "invented-space")
    {
        byte[] numbers = new byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(numbers, kind);
        BinaryPrimitives.WriteUInt32LittleEndian(numbers.AsSpan(4), id);
        return [0,0,0,0, ..LocalSessionSearchChecks.Ddl(space), ..numbers];
    }
    internal static byte[] Request(byte[] body = null, uint call = 0x12345678) =>
        LocalSessionCreationChecks.Request(call, body ?? Body(), "MatchmakingProtocol::ReportJoinSuccess_V1");
    internal static byte[] Response(uint call = 0x12345678)
    {
        byte[] result = [0,0,0,0, ..LocalSessionSearchChecks.Ddl("MatchmakingProtocol"), 0,1, 0,0,0,0,
            ..LocalSessionSearchChecks.Ddl("MatchmakingProtocol::ReportJoinSuccess_V1*")];
        BinaryPrimitives.WriteUInt32LittleEndian(result, (uint)(result.Length - 4));
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(28), call); return result;
    }
    internal static int Run()
    {
        int passed = 0;
        void Check(bool b, string why) { if (!b) throw new Exception(why); passed++; }
        // Independent transcription from E532D6..E53303, no account/packet data.
        byte[] vector = [0,0,0,0, 2,0,0x73,0, 0,0,0,0, 0x44,0x33,0x22,0x11];
        Check(LocalSessionMetadata.TryReadJoinSuccessBody(vector, out var space, out uint id)
            && space.SequenceEqual("s"u8) && id == 0x11223344, "Native success report layout");
        using var host = RegisteredHostChecks.CreateRegistered();
        using var guest = RegisteredHostChecks.CreateRegistered();
        object owner = new(), visitor = new();
        using var registry = new LocalSessionRegistry(catalogueProbe:true);
        Check(registry.TryCreate(owner, host, LocalSessionCatalogueChecks.PublicBody(), out _, out _), "Success host fixture");
        bool Reply(byte[] message, object caller = null, LocalLoginRpcEngine rpc = null) =>
            LocalSessionJoinSuccessCodec.TryReply(message, registry, caller ?? visitor, rpc ?? guest, out _, out _);
        Check(!Reply(Request()), "Unreserved caller confirmed");
        Check(LocalSessionJoinCodec.TryReply(LocalSessionJoinChecks.Request(), registry, visitor, guest, out _, out _), "Success reservation fixture");
        byte[] body = Body(), request = Request();
        for (int i=0; i<body.Length; i++) Check(!Reply(Request(body[..i])), "Truncated success body accepted");
        for (int i=0; i<request.Length-body.Length; i++)
        {
            var partial = request[..i];
            if (i>=4) BinaryPrimitives.WriteUInt32LittleEndian(partial, (uint)(i-4));
            Check(!Reply(partial), "Truncated success header accepted");
        }
        foreach (var bad in new byte[][] { [..body,0], [1,0,0,0,..body[4..]], Body(kind:1), Body(id:0),
            Body(id:uint.MaxValue), Body(id:2), Body(space:"other"), Body(space:new string('x',1025)), new byte[8193] })
            Check(!Reply(Request(bad)), "Invalid success scope accepted");
        Check(!Reply(Request(), new object()), "Foreign transport confirmed reservation");
        Check(!Reply(Request(), rpc:host), "Foreign registration confirmed reservation");
        Check(!Reply(Request(), owner, host), "Host confirmed guest reservation");
        Check(!LocalSessionJoinSuccessCodec.TryReply(Request(), registry, visitor, null, out _, out _), "Missing registration confirmed");
        Check(!Reply(LocalSessionJoinChecks.Request()), "Wrong method confirmed");
        Check(registry.TryCopyLiveSession(visitor, "invented-space"u8, 1, out var pending), "Pending snapshot");
        using(pending) Check(pending.PendingProfiles.Count==1 && pending.ConfirmedProfiles.Count==0, "Rejected success mutated membership");
        foreach(uint call in new uint[]{0,0x12345678,uint.MaxValue})
            Check(LocalSessionJoinSuccessCodec.TryReply(Request(call:call), registry, visitor, guest, out var response, out var reason)
                && response.SequenceEqual(Response(call)) && reason == (call==0 ? "local-join-member-confirmed" : "local-join-success-replayed"),
                "Success response correlation or replay");
        Check(registry.TryCopyLiveSession(owner, "invented-space"u8, 1, out var joined), "Confirmed snapshot");
        byte[] owned;
        using(joined)
        {
            Check(joined.PendingProfiles.Count==0 && joined.ConfirmedProfiles.Count==1, "Confirmation not projected");
            Check(BinaryPrimitives.ReadInt64LittleEndian(joined.Metadata.Attributes[
                Convert.ToHexString("settlers_free_slots"u8)].AsSpan(1))==2, "Confirmation released reserved capacity");
            owned = joined.ConfirmedProfiles.Single();
            // Verify actual GetSession serializer member state, not only in-memory state.
            byte[] response = LocalSessionJoinCodec.Encode(7, joined);
            byte[] member = [..owned, 3,0,0,0];
            Check(response.AsSpan().IndexOf(member)>=0, "Confirmed member state missing from wire");
        }
        Check(owned.All(b=>b==0), "Confirmed snapshot did not clear owned profile");
        Check(!registry.TryUpdate(visitor, LocalSessionUpdateChecks.Body(), out _), "Confirmation granted host privilege");
        Check(!registry.TryCreate(visitor, guest, LocalSessionCatalogueChecks.PublicBody(), out _, out _), "Member hosted concurrently");
        Check(registry.TryLeave(visitor, LocalSessionLeaveChecks.Body(), out var left) && left=="local-session-confirmed-member-left", "Confirmed leave");
        Check(!Reply(Request()), "Left member reconfirmed");
        Check(LocalSessionJoinCodec.TryReply(LocalSessionJoinChecks.Request(), registry, visitor, guest, out _, out _)
            && Reply(Request()), "Rejoin confirmation failed");
        registry.RemoveOwner(visitor);
        Check(!Reply(Request()) && registry.Count==1, "Transport cleanup retained membership or removed host");
        using var disabled = new LocalSessionRegistry();
        Check(!LocalSessionJoinSuccessCodec.TryReply(Request(), disabled, visitor, guest, out _, out _), "Disabled catalogue confirmed");
        registry.Dispose(); Check(!Reply(Request()), "Closed registry confirmed");
        return passed;
    }
}
