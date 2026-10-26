using System.Buffers.Binary;
using System.Text;
using S7Patcher.Source;

internal static class LocalSessionDisplayChecks
{
    private static byte[] Ddl(string text) => LocalSessionSearchChecks.Ddl(text);
    private static byte[] Map(params byte[][] entries) => LocalSessionUpdateChecks.Map(entries);
    internal const string Route = "prudp:/address=127.0.0.1;port=40001;RVCID=77;Storm=RoutingOption{invented}";
    internal static byte[] Attributes() => Map(
        [.. Ddl("echo_session_guid"), 4, .. Ddl("00000000-0000-0000-0000-000000000077")],
        [.. Ddl("session_descriptor_type"), 6, 77, 0, 0, 0, 0, 0, 0, 0],
        [.. Ddl("settlers_session_name"), 4, .. Ddl("invented original title")],
        [.. Ddl("settlers_map_name"), 4, .. Ddl("invented map")],
        [.. Ddl("settlers_max_slots"), 6, 4, 0, 0, 0, 0, 0, 0, 0],
        [.. Ddl("settlers_free_slots"), 6, 3, 0, 0, 0, 0, 0, 0, 0],
        [.. Ddl("settlers_extra_version_number"), 6, 99, 0, 0, 0, 0, 0, 0, 0]);
    internal static byte[] CreateBody(string route = Route, byte[] attributes = null) =>
        [0, 0, 0, 0, .. Ddl("invented-space"), .. (attributes ?? Attributes()), .. Ddl(route),
         0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1];
    internal static byte[] Search(string space = "invented-space", string selector = "default_query", uint limit = 100, byte[] filters = null)
    {
        byte[] count = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(count, limit);
        return LocalSessionSearchChecks.Request(body: [2, 0, 0, 0, .. Ddl("MatchmakingSession"), 1, 0,
            .. Ddl("MatchmakingSessionMember"), 1, 0, .. Ddl(space), .. Ddl(selector), .. (filters ?? Map()), .. count]);
    }

    // Independent BinaryReader walk of the native E4F100 layout. Deliberately
    // separate from production Writer and verifies exact field boundaries/end.
    internal static void Verify(byte[] response, ReadOnlySpan<byte> host, uint id = 1, bool updated = false)
    {
        void Require(bool value) { if (!value) throw new Exception("Native display response layout mismatch"); }
        using BinaryReader reader = new(new MemoryStream(response));
        string Text()
        {
            ushort length = reader.ReadUInt16();
            Require(length > 0);
            byte[] bytes = reader.ReadBytes(length); Require(bytes.Length == length && bytes[^1] == 0);
            return Encoding.ASCII.GetString(bytes, 0, length - 1);
        }
        Require(reader.ReadUInt32() == response.Length - 4);
        Require(Text() == "MatchmakingProtocol" && reader.ReadByte() == 0 && reader.ReadByte() == 1);
        Require(reader.ReadUInt32() == 0x12345678 && Text() == "MatchmakingProtocol::SearchSessions_V1*");
        Require(reader.ReadUInt32() == 1 && reader.ReadUInt32() == id && reader.ReadUInt32() == 0);
        Require(Text() == "" && reader.ReadUInt64() == 0 && reader.ReadUInt32() == 0 && reader.ReadUInt32() == 0);
        Require(reader.ReadByte() == 0 && reader.ReadByte() == 0 && reader.ReadUInt32() == 1);
        Require(reader.ReadBytes(16).AsSpan().SequenceEqual(host) && reader.ReadUInt32() == 2);
        Require(reader.ReadUInt32() == 7);
        var texts = new Dictionary<string, string>(); var numbers = new Dictionary<string, ulong>();
        for (int i = 0; i < 7; i++)
        {
            string key = Text(); byte tag = reader.ReadByte();
            if (tag == 4) texts.Add(key, Text());
            else { Require(tag == 6); numbers.Add(key, reader.ReadUInt64()); }
        }
        Require(texts["settlers_session_name"] == LocalSessionDisplayCodec.Title
            && texts["echo_session_guid"] == "00000000-0000-0000-0000-000000000077"
            && texts["settlers_map_name"] == (updated ? "updated map" : "invented map"));
        Require(numbers["session_descriptor_type"] == 77 && numbers["settlers_max_slots"] == 4
            && numbers["settlers_free_slots"] == 3 && numbers["settlers_extra_version_number"] == 99);
        if (updated)
        {
            Require(reader.ReadUInt32() == 1 && Text() == "invented member metadata" && reader.ReadUInt32() == 1);
            Require(reader.ReadBytes(16).All(b => b == 0x71) && reader.ReadByte() == 3 && reader.ReadByte() == 1);
        }
        else Require(reader.ReadUInt32() == 0);
        Require(reader.ReadUInt32() == 1 && reader.ReadUInt32() == id
            && Text() == Route && reader.BaseStream.Position == reader.BaseStream.Length);
    }

    internal static int Run()
    {
        int passed = 0;
        void Check(bool value, string label) { if (!value) throw new Exception(label); passed++; }
        using var registration = RegisteredHostChecks.CreateRegistered();
        registration.TryCopyRegisteredPeer(out var host);
        using var hostLifetime = host;
        object owner = new(), stranger = new();
        byte[] search = Search();
        using var disabled = new LocalSessionRegistry();
        Check(disabled.TryCreate(owner, registration, CreateBody(), out _, out _) && disabled.TryLeave(owner, LocalSessionLeaveChecks.Body(), out _), "Disabled setup");
        Check(!disabled.TryCopyDisplaySnapshot(owner, out _) && !LocalSessionDisplayCodec.TryReply(search, disabled, owner, out _, out _), "Probe enabled by default");
        using var registry = new LocalSessionRegistry(displayProbe: true);
        Check(LocalSessionDisplayCodec.TryReply(search, registry, owner, out var empty, out _) && empty.SequenceEqual(LocalSessionSearchChecks.EmptyResponse()), "No preview must be empty");
        Check(registry.TryCreate(owner, registration, CreateBody(), out _, out _), "Create setup");
        Check(!LocalSessionDisplayCodec.TryReply(search, registry, owner, out _, out _), "Live catalogue must not be faked");
        Check(!registry.TryLeave(stranger, LocalSessionLeaveChecks.Body(), out _) && !registry.TryCopyDisplaySnapshot(stranger, out _), "Other owner captured preview");
        Check(registry.TryLeave(owner, LocalSessionLeaveChecks.Body(), out _) && registry.Count == 0, "Leave must remove real session");
        Check(!registry.TryUpdate(owner, LocalSessionUpdateChecks.Body(), out _) && !registry.TryLeave(owner, LocalSessionLeaveChecks.Body(), out _), "Preview acted like live record");
        Check(LocalSessionDisplayCodec.TryReply(search, registry, owner, out var reply, out var reason)
            && reason == "local-session-display-probe-response-created", "Display encode failed");
        Verify(reply, host.ProfileId); passed++;
        Check(registry.TryCopyDisplaySnapshot(owner, out var unchanged), "Original snapshot missing");
        using (unchanged)
            Check(Encoding.ASCII.GetString(unchanged.Metadata.Attributes[Convert.ToHexString("settlers_session_name"u8)])
                .Contains("invented original title"), "Diagnostic title mutated source metadata");
        Check(LocalSessionDisplayCodec.TryReply(search, registry, stranger, out empty, out _) && empty.SequenceEqual(LocalSessionSearchChecks.EmptyResponse()), "Preview leaked to other owner");
        foreach (byte[] query in new[] { Search(limit: 0), Search(space: "other"), Search(filters: Map([.. Ddl("string4"), 4, .. Ddl("Group")])) })
            Check(LocalSessionDisplayCodec.TryReply(query, registry, owner, out empty, out _) && empty.SequenceEqual(LocalSessionSearchChecks.EmptyResponse()), "Space/zero-limit/Group restriction ignored");
        Check(!LocalSessionDisplayCodec.TryReply(Search(selector: "unknown"), registry, owner, out _, out _), "Unknown selector accepted");
        Check(!LocalSessionDisplayCodec.TryReply(Search(filters: Map([.. Ddl("string4"), 0])), registry, owner, out _, out _), "Wrong kind-filter type accepted");
        for (int i = 0; i < search.Length; ++i)
        {
            byte[] partial = search[..i];
            if (i >= 4) BinaryPrimitives.WriteUInt32LittleEndian(partial, (uint)(i - 4));
            Check(!LocalSessionDisplayCodec.TryReply(partial, registry, owner, out var invalid, out _) && invalid == null, "Truncated query accepted");
        }
        Check(!LocalSessionSearchCodec.TryReadQuery(Search(filters: Map([.. Ddl("x"), 0], [.. Ddl("x"), 0])), out _), "Duplicate filter accepted");
        byte[] mutable = Search(filters: Map([.. Ddl("x"), 4, .. Ddl("invented")]));
        Check(LocalSessionSearchCodec.TryReadQuery(mutable, out var owned), "Query copy failed");
        Array.Clear(mutable);
        Check(owned.Space.AsSpan().SequenceEqual("invented-space"u8) && owned.Limit == 100 && owned.Filters.Count == 1, "Query aliases input");
        byte[] querySpace = owned.Space, filterValue = owned.Filters.Values.Single(); owned.Dispose();
        Check(querySpace.All(b => b == 0) && filterValue.All(b => b == 0) && owned.Filters.Count == 0, "Query cleanup failed");
        Check(registry.TryCopyDisplaySnapshot(owner, out var copy), "Snapshot copy failed");
        Check(registry.TryCreate(owner, registration, CreateBody(), out uint second, out _) && second == 2
            && !registry.TryCopyDisplaySnapshot(owner, out _), "Recreate did not invalidate preview");
        Check(copy.Metadata.Attributes.Count == 7 && copy.Host.ProfileId.SequenceEqual(host.ProfileId), "Copy invalidated by removal");
        byte[] spaceStorage = copy.Space; byte[] attrStorage = copy.Metadata.Attributes.Values.First(); copy.Dispose();
        Check(spaceStorage.All(b => b == 0) && attrStorage.All(b => b == 0), "Snapshot buffers not cleared");
        Check(registry.TryLeave(owner, LocalSessionLeaveChecks.Body(id: 2), out _), "Second leave failed");
        registry.RemoveOwner(owner);
        Check(!registry.TryCopyDisplaySnapshot(owner, out _), "Disconnected owner kept preview");
        using var oversized = new LocalSessionRegistry(true);
        Check(oversized.TryCreate(owner, registration, CreateBody(new string('r', 6000)), out _, out _), "Overflow setup failed");
        Check(oversized.TryUpdate(owner, LocalSessionUpdateChecks.Body(attributes: Map([.. Ddl("padding"), 4, .. Ddl(new string('a', 60000))])), out _), "Overflow update failed");
        Check(oversized.TryLeave(owner, LocalSessionLeaveChecks.Body(), out _)
            && !LocalSessionDisplayCodec.TryReply(search, oversized, owner, out var tooBig, out reason)
            && tooBig == null && reason == "display-probe-response-too-large", "Oversized result truncated/returned");
        using var incomplete = new LocalSessionRegistry(true);
        Check(incomplete.TryCreate(owner, registration, LocalSessionCreationChecks.Body(), out _, out _)
            && incomplete.TryLeave(owner, LocalSessionLeaveChecks.Body(), out _)
            && !LocalSessionDisplayCodec.TryReply(search, incomplete, owner, out _, out reason)
            && reason == "display-probe-missing-native-attributes", "Missing descriptor fields invented");
        registry.Dispose();
        Check(!registry.TryCopyDisplaySnapshot(owner, out _), "Disposed registry revived");
        using var updated = new LocalSessionRegistry(true);
        Check(updated.TryCreate(owner, registration, CreateBody(), out _, out _), "Updated setup failed");
        Check(updated.TryUpdate(owner, LocalSessionUpdateChecks.Body(
            attributes: Map([.. Ddl("settlers_map_name"), 4, .. Ddl("updated map")]),
            members: Map([.. Ddl("invented member metadata"), .. Map([.. Enumerable.Repeat((byte)0x71, 16), 3, 1])])), out _), "Metadata update failed");
        Check(updated.TryLeave(owner, LocalSessionLeaveChecks.Body(), out _)
            && LocalSessionDisplayCodec.TryReply(search, updated, owner, out reply, out _), "Updated display failed");
        Verify(reply, host.ProfileId, updated: true); passed++;
        using var noRoute = new LocalSessionRegistry(true);
        Check(noRoute.TryCreate(owner, registration, CreateBody(route: ""), out _, out _)
            && noRoute.TryLeave(owner, LocalSessionLeaveChecks.Body(), out _)
            && !LocalSessionDisplayCodec.TryReply(search, noRoute, owner, out _, out reason)
            && reason == "display-probe-missing-game-route", "Authentication URL substituted for missing game route");
        return passed;
    }
}
