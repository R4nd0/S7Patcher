using System.Buffers.Binary;
using System.Text;
using S7Patcher.Source;

internal static class LocalSessionJoinChecks
{
    private static byte[] Text(string s) => LocalSessionSearchChecks.Ddl(s);
    internal static byte[] Body(byte[] profile = null, uint id = 1, string space = "invented-space")
    {
        byte[] number = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(number, id);
        return [2,0,0,0, ..Text("MatchmakingSession"),1,0, ..Text("MatchmakingSessionMember"),1,0,
            ..Text(space), ..number, ..(profile == null ? new byte[4]
            : (byte[])[1,0,0,0, ..Text("player_setting"),1,0,0,0, ..profile,3,1])];
    }
    internal static byte[] Request(byte[] body = null) => LocalSessionCreationChecks.Request(
        method: "MatchmakingProtocol::JoinSession_V1", body: body ?? Body());
    private static string ReadText(BinaryReader reader)
    {
        int count = reader.ReadUInt16(); var bytes = reader.ReadBytes(count);
        if (count < 1 || bytes.Length != count || bytes[^1] != 0) throw new Exception("Join text boundary");
        return Encoding.ASCII.GetString(bytes, 0, count - 1);
    }
    internal static int Run()
    {
        int passed = 0;
        void Check(bool b, string why) { if (!b) throw new Exception(why); ++passed; }
        using var host = RegisteredHostChecks.CreateRegistered();
        using var guest = RegisteredHostChecks.CreateRegistered();
        host.TryCopyRegisteredPeer(out var hostPeer); guest.TryCopyRegisteredPeer(out var guestPeer);
        using var hp = hostPeer; using var gp = guestPeer;
        object owner = new(), visitor = new();
        using var registry = new LocalSessionRegistry(catalogueProbe: true);
        Check(registry.TryCreate(owner, host, LocalSessionCatalogueChecks.PublicBody(), out _, out _), "Join fixture");
        bool Reply(byte[] body, out byte[] response) => LocalSessionJoinCodec.TryReply(Request(body), registry, visitor, guest, out response, out _);
        byte[] own = Body(gp.ProfileId.ToArray());
        for (int i = 0; i < own.Length; ++i) Check(!Reply(own[..i], out _), "Truncated join accepted");
        Check(!Reply(Body(hp.ProfileId.ToArray()), out _), "Foreign metadata identity accepted");
        Check(!Reply(Body(id: 99), out _), "Unknown session accepted");
        Check(!Reply(Body(space: "other"), out _), "Cross-space join accepted");
        Check(!LocalSessionJoinCodec.TryReply(Request(), registry, owner, host, out _, out _), "Self join accepted");
        Check(!LocalSessionJoinCodec.TryReply(Request(), registry, visitor, null, out _, out _), "Unregistered join");
        Check(!registry.TryJoin(visitor, guest, own, _ => null, out _, out _), "Serialization failure accepted");
        Check(registry.TryCopyLiveSession(visitor, "invented-space"u8, 1, out var before), "Pre-reservation read");
        using (before) Check(before.PendingProfiles.Count == 0 && before.Metadata.Members.Count == 0, "Failed encode changed registry");
        Check(Reply(own, out byte[] response), "Valid pending join rejected");
        using (var reader = new BinaryReader(new MemoryStream(response)))
        {
            Check(reader.ReadUInt32() == response.Length - 4 && ReadText(reader) == "MatchmakingProtocol", "Join envelope");
            Check(reader.ReadByte() == 0 && reader.ReadByte() == 1 && reader.ReadUInt32() == 0x12345678, "Join correlation");
            Check(ReadText(reader) == "MatchmakingProtocol::JoinSession_V1*" && ReadText(reader) == LocalSessionDisplayChecks.Route, "Join route output");
            Check(reader.ReadUInt32() == 1 && reader.ReadUInt32() == 0 && ReadText(reader) == "", "Session prefix");
            Check(reader.ReadUInt64() == 0 && reader.ReadUInt32() == 0 && reader.ReadUInt32() == 0 && reader.ReadUInt16() == 0, "Session defaults");
            Check(reader.ReadUInt32() == 2, "Member list count");
            Check(reader.ReadBytes(16).AsSpan().SequenceEqual(hp.ProfileId) && reader.ReadUInt32() == 2, "Host member");
            Check(reader.ReadBytes(16).AsSpan().SequenceEqual(gp.ProfileId) && reader.ReadUInt32() == 0, "Pending member must not be marked joined");
            Check(reader.ReadUInt32() == 8, "Attributes count");
            for (int i = 0; i < 8; ++i)
            {
                string key = ReadText(reader); byte tag = reader.ReadByte();
                if (tag == 4) ReadText(reader);
                else if (tag == 3) reader.ReadByte();
                else { long v = reader.ReadInt64(); if (key == "settlers_free_slots") Check(v == 2, "Reservation capacity not reflected"); }
            }
            Check(reader.ReadUInt32() == 1 && ReadText(reader) == "player_setting" && reader.ReadUInt32() == 1, "Member metadata groups");
            Check(reader.ReadBytes(16).AsSpan().SequenceEqual(gp.ProfileId) && reader.ReadUInt16() == 0x0103, "Member metadata payload");
            Check(reader.BaseStream.Position == reader.BaseStream.Length, "Trailing join bytes");
        }
        Check(Reply(own, out var replay) && response.SequenceEqual(replay), "Join replay changed result");
        Check(!Reply(Body(), out _), "Changed replay accepted");
        Check(!registry.TryUpdate(visitor, LocalSessionUpdateChecks.Body(), out _), "Pending guest changed host settings");
        Check(!registry.TryCreate(visitor, guest, LocalSessionCatalogueChecks.PublicBody(), out _, out _), "Pending guest hosted concurrently");
        Check(!LocalSessionJoinCodec.TryReply(Request(), registry, new object(), guest, out _, out _), "Same identity reserved twice");
        var guests = new List<LocalLoginRpcEngine>();
        try
        {
            for (int i = 0; i < 3; ++i)
            {
                var additional = RegisteredHostChecks.CreateRegistered(); guests.Add(additional);
                bool admitted = LocalSessionJoinCodec.TryReply(Request(), registry, new object(), additional, out _, out _);
                Check(admitted == (i < 2), "Four-slot capacity not enforced");
            }
        }
        finally { foreach (var additional in guests) additional.Dispose(); }
        Check(registry.TryLeave(visitor, LocalSessionLeaveChecks.Body(), out _), "Pending leave failed");
        Check(registry.Count == 1, "Guest leave removed host");
        Check(registry.TryCopyLiveSession(visitor, "invented-space"u8, 1, out var after), "Guest leave removed session");
        using (after) Check(after.PendingProfiles.Count == 2 && after.Metadata.Members.Count == 0, "Guest leave retained metadata or removed another guest");
        Check(Reply(own, out _), "Rejoin after leave"); registry.RemoveOwner(visitor);
        Check(Reply(own, out _), "Rejoin after transport cleanup");
        registry.RemoveOwner(owner); Check(!Reply(own, out _), "Join removed host");
        foreach (string bad in new[] { "", "prudp:/address=192.0.2.1;port=40001", LocalSessionDisplayChecks.Route + "|",
            LocalSessionDisplayChecks.Route + ";redirected=1", "prudp:/address=127.0.0.1;port=0" })
            Check(!LocalSessionRegistry.HostRoutesOwned(Encoding.ASCII.GetBytes(bad), hp), "Unsafe host route");
        Check(LocalSessionRegistry.HostRoutesOwned(Encoding.ASCII.GetBytes(LocalSessionDisplayChecks.Route), hp), "Owned game port route rejected");
        foreach (var (route, suffix) in new[] {
            ("", "empty"), (new string('x', 2049), "too-long"), ("prudp:/address=127.0.0.1;port=4\n", "non-ascii"),
            (string.Join('|', Enumerable.Repeat(LocalSessionDisplayChecks.Route, 5)), "count"),
            (LocalSessionDisplayChecks.Route + "|", "empty-item"), ("udp:/address=127.0.0.1;port=4", "scheme"),
            (LocalSessionDisplayChecks.Route + "#x=1", "section"), (LocalSessionDisplayChecks.Route + ";x=%20", "escaped"),
            ("prudp:/address=127.0.0.1;port=0", "syntax"), ("prudp:/address=0.0.0.0;port=4", "unspecified"),
            ("prudp:/address=192.0.2.1;port=4", "address-mismatch"),
            (LocalSessionDisplayChecks.Route + ";redirected=1", "redirected") })
        {
            Check(!LocalSessionRegistry.HostRoutesOwned(Encoding.ASCII.GetBytes(route), hp, out var diagnosis)
                && diagnosis == "local-join-host-route-" + suffix, "Wrong bounded route diagnosis: " + suffix);
        }
        Check(LocalSessionRegistry.HostRoutesOwned(Encoding.ASCII.GetBytes(LocalSessionDisplayChecks.Route), hp,
            out var ownedReason) && ownedReason == "local-join-host-route-owned", "Valid route diagnosis");
        // The reported route failure must propagate through the real join handler,
        // without reserving a member or invoking the response encoder.
        using var invalidRouteRegistry = new LocalSessionRegistry(catalogueProbe: true);
        byte[] invalidCreate = LocalSessionCatalogueChecks.PublicBody();
        byte[] validRoute = Encoding.ASCII.GetBytes(LocalSessionDisplayChecks.Route);
        int routeOffset = invalidCreate.AsSpan().IndexOf(validRoute);
        Check(routeOffset >= 0, "Route fixture not found");
        invalidCreate[routeOffset] = (byte)'x';
        Check(invalidRouteRegistry.TryCreate(owner, host, invalidCreate, out _, out _), "Malformed route fixture");
        Check(!invalidRouteRegistry.TryJoin(visitor, guest, own, _ => throw new Exception("Invalid route encoded"),
            out _, out var rejectedReason) && rejectedReason == "local-join-host-route-scheme", "Join lost route diagnosis");
        Check(invalidRouteRegistry.TryCopyLiveSession(visitor, "invented-space"u8, 1, out var untouched), "Route diagnostic snapshot");
        using (untouched) Check(untouched.PendingProfiles.Count == 0, "Rejected route reserved membership");
        using var privateRegistry = new LocalSessionRegistry(catalogueProbe: true);
        Check(privateRegistry.TryCreate(owner, host, LocalSessionCatalogueChecks.PublicBody(true), out _, out _), "Private fixture");
        Check(!LocalSessionJoinCodec.TryReply(Request(), privateRegistry, visitor, guest, out _, out _), "Private join accepted");
        using var disabled = new LocalSessionRegistry();
        Check(disabled.TryCreate(owner, host, LocalSessionCatalogueChecks.PublicBody(), out _, out _), "Disabled fixture");
        Check(!LocalSessionJoinCodec.TryReply(Request(), disabled, visitor, guest, out _, out _), "Join enabled outside catalogue mode");
        return passed;
    }
}
