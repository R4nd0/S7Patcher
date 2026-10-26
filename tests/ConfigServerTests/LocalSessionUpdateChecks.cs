using System.Buffers.Binary;
using System.Text;
using S7Patcher.Source;

internal static class LocalSessionUpdateChecks
{
    private static byte[] Ddl(string text) => LocalSessionSearchChecks.Ddl(text);
    private static string Key(string text) => Convert.ToHexString(Encoding.ASCII.GetBytes(text));
    internal static byte[] Map(params byte[][] entries)
    {
        byte[] count = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(count, (uint)entries.Length);
        return [.. count, .. entries.SelectMany(e => e)];
    }
    internal static byte[] Body(uint id = 1, string space = "invented-space", byte[] attributes = null, byte[] members = null)
    {
        byte[] number = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(number, id);
        return [0, 0, 0, 0, .. Ddl(space), .. number, .. (attributes ?? Map([.. Ddl("attribute"), 3, 1])), .. (members ?? Map())];
    }
    internal static byte[] Request(uint callId = 0x12345678, byte[] body = null) =>
        LocalSessionCreationChecks.Request(callId, body ?? Body(), "MatchmakingProtocol::UpdateSession_V1");
    internal static byte[] Response(uint callId = 0x12345678)
    {
        byte[] result = [0, 0, 0, 0, .. Ddl("MatchmakingProtocol"), 0, 1, 0, 0, 0, 0,
            .. Ddl("MatchmakingProtocol::UpdateSession_V1*")];
        BinaryPrimitives.WriteUInt32LittleEndian(result, (uint)(result.Length - 4));
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(28), callId);
        return result;
    }
    internal static int Run()
    {
        using LocalLoginRpcEngine registration = RegisteredHostChecks.CreateRegistered();
        int passed = 0;
        void Check(bool value, string label) { if (!value) throw new Exception(label); passed++; }
        using LocalSessionRegistry registry = new(); object owner = new();
        Check(!LocalSessionUpdateCodec.TryReply(Request(), registry, owner, out _, out _), "Update created a nonexistent session");
        Check(registry.TryCreate(owner, registration, LocalSessionCreationChecks.Body(), out uint id, out _) && id == 1, "Setup create failed");
        void Reject(byte[] message, object requester = null)
        {
            Check(!LocalSessionUpdateCodec.TryReply(message, registry, requester ?? owner, out var reply, out _)
                && reply == null && registry.Count == 1, "Invalid update accepted or registry changed");
        }
        byte[] initial = [4, .. Ddl("invented-value")];
        Check(registry.TryGetMetadata(owner, 1, out var snapshot), "Missing initial metadata");
        using (snapshot)
        {
            Check(snapshot.Attributes[Key("attribute")].SequenceEqual(initial)
                && snapshot.Members[Key("members")][new string('0', 32)].SequenceEqual(initial), "Create metadata lost");
        }
        byte[] body = Body(), message = Request();
        for (int i = 0; i < body.Length; ++i) Reject(Request(body: body[..i]));
        for (int i = 0; i < message.Length - body.Length; ++i)
        {
            byte[] partial = message[..i];
            if (i >= 4) BinaryPrimitives.WriteUInt32LittleEndian(partial, (uint)(i - 4));
            Reject(partial);
        }
        Reject(Request(body: [.. body, 0]));
        Reject(Request(body: Body(id: 0))); Reject(Request(body: Body(id: uint.MaxValue)));
        Reject(Request(body: Body(space: "other-space"))); Reject(Request(), new object());
        Reject(LocalSessionCreationChecks.Request()); Reject(new byte[65537]);
        byte[] wrong = (byte[])body.Clone(); wrong[0] = 1; Reject(Request(body: wrong));
        Reject(Request(body: Body(attributes: Map([.. Ddl("x"), 8]))));
        Reject(Request(body: Body(attributes: Map([.. Ddl("same"), 0], [.. Ddl("same"), 0]))));
        Reject(Request(body: Body(members: Map([.. Ddl("same"), .. Map()], [.. Ddl("same"), .. Map()]))));
        Reject(Request(body: Body(members: Map([.. Ddl("x"), .. Map([.. new byte[16], 0], [.. new byte[16], 0])]))));
        Reject(Request(body: Body(attributes: Map(Enumerable.Range(0, 65).Select(i => (byte[])[.. Ddl("k" + i), 0]).ToArray()))));
        Random random = new(20261026);
        for (int i = 0; i < 100; ++i)
        {
            byte[] malformed = new byte[random.Next(0, 200)]; random.NextBytes(malformed); Reject(Request(body: malformed));
        }
        Check(registry.TryGetMetadata(owner, 1, out snapshot), "Rejected updates removed record");
        using (snapshot) Check(snapshot.Attributes.Count == 1 && snapshot.Attributes[Key("attribute")].SequenceEqual(initial), "Rejected update changed metadata");

        byte[] nested = Map([.. Ddl("members"), .. Map([.. new byte[16], 3, 0])]);
        byte[] update = Body(attributes: Map([.. Ddl("new-field"), 7, .. new byte[16]]), members: nested);
        foreach (uint callId in new uint[] { 0, 0x12345678, uint.MaxValue })
            Check(LocalSessionUpdateCodec.TryReply(Request(callId, update), registry, owner, out var response, out var reason)
                && response.SequenceEqual(Response(callId)) && reason == "local-session-metadata-updated" && registry.Count == 1,
                "Update/retry response differs from native void layout");
        Check(registry.TryGetMetadata(owner, 1, out snapshot), "Updated metadata unavailable");
        byte[] owned;
        using (snapshot)
        {
            Check(snapshot.Attributes.Count == 2 && snapshot.Attributes[Key("attribute")].SequenceEqual(initial)
                && snapshot.Members[Key("members")][new string('0', 32)].SequenceEqual(new byte[] { 3, 0 }),
                "Update did not merge nested values while retaining other keys");
            owned = snapshot.Attributes[Key("attribute")]; owned[0] = 255;
        }
        Check(owned.All(b => b == 0), "Snapshot disposal retained value buffer");
        Check(registry.TryGetMetadata(owner, 1, out snapshot), "Snapshot isolation failed");
        using (snapshot) Check(snapshot.Attributes[Key("attribute")].SequenceEqual(initial), "Snapshot mutated stored values");
        Check(!registry.TryGetMetadata(new object(), 1, out _), "Snapshot ignored owner");
        foreach (byte tag in Enumerable.Range(0, 8).Select(x => (byte)x))
        {
            byte[] encoded = [tag, .. (tag == 4 ? Ddl("value") : new byte[tag switch { 0 => 0, 3 => 1, 7 => 16, _ => 8 }])];
            Check(LocalSessionUpdateCodec.TryReply(Request(body: Body(attributes: Map([.. Ddl("variant"), .. encoded]))), registry, owner, out _, out _), "Variant update rejected");
        }
        byte[][] fill = Enumerable.Range(0, 61).Select(i => (byte[])[.. Ddl("k" + i), 0]).ToArray();
        Check(registry.TryUpdate(owner, Body(attributes: Map(fill)), out _), "Aggregate count at limit rejected");
        Reject(Request(body: Body(attributes: Map([.. Ddl("attribute"), 0], [.. Ddl("overflow"), 0]))));
        Check(registry.TryGetMetadata(owner, 1, out snapshot), "Capacity rejection removed state");
        using (snapshot) Check(snapshot.Attributes.Count == 64 && snapshot.Attributes[Key("attribute")].SequenceEqual(initial), "Capacity rejection partially applied update");
        // Two individually valid updates must not accumulate beyond the state-byte cap.
        using LocalSessionRegistry bytesRegistry = new();
        Check(bytesRegistry.TryCreate(owner, registration, LocalSessionCreationChecks.Body(), out _, out _), "Byte-limit setup failed");
        byte[] large = [4, .. Ddl(new string('z', 33000))];
        Check(bytesRegistry.TryUpdate(owner, Body(attributes: Map([.. Ddl("large-one"), .. large])), out _), "Valid large value rejected");
        Check(!bytesRegistry.TryUpdate(owner, Body(attributes: Map([.. Ddl("large-two"), .. large])), out var limitReason)
            && limitReason == "local-session-metadata-limit", "Aggregate byte cap bypassed");
        Check(bytesRegistry.TryGetMetadata(owner, 1, out snapshot), "Byte limit removed state");
        using (snapshot) Check(snapshot.Attributes.Count == 2 && !snapshot.Attributes.ContainsKey(Key("large-two")), "Byte limit partially applied update");
        Check(registry.TryCreate(owner, registration, LocalSessionCreationChecks.Body(), out uint same, out _) && same == 1, "Metadata update broke create idempotence");
        registry.RemoveOwner(owner);
        Check(registry.Count == 0 && !registry.TryUpdate(owner, Body(), out _) && !registry.TryGetMetadata(owner, 1, out _), "Removed session still editable");
        return passed;
    }
}
