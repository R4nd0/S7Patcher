using System.Buffers.Binary;
using System.Text;
using S7Patcher.Source;

internal static class LocalSessionCatalogueChecks
{
    private static byte[] Ddl(string value) => LocalSessionSearchChecks.Ddl(value);
    private static byte[] Map(params byte[][] entries) => LocalSessionUpdateChecks.Map(entries);
    internal static byte[] PublicBody(bool isPrivate = false, string route = LocalSessionDisplayChecks.Route)
    {
        var old = LocalSessionDisplayChecks.Attributes();
        byte[] attributes = [.. old, .. Ddl("private"), 3, (byte)(isPrivate ? 1 : 0)];
        BinaryPrimitives.WriteUInt32LittleEndian(attributes, 8);
        return LocalSessionDisplayChecks.CreateBody(route: route, attributes: attributes);
    }
    internal static byte[] Get(uint id = 1, string space = "invented-space")
    {
        byte[] number = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(number, id);
        return LocalSessionCreationChecks.Request(method: "MatchmakingProtocol::GetSession_V1", body:
            [2,0,0,0, .. Ddl("MatchmakingSession"),1,0, .. Ddl("MatchmakingSessionMember"),1,0, .. Ddl(space), .. number]);
    }
    private static void Require(bool result) { if (!result) throw new Exception("Catalogue wire mismatch"); }
    private static string Text(BinaryReader reader)
    {
        int size = reader.ReadUInt16(); Require(size > 0);
        byte[] value = reader.ReadBytes(size); Require(value.Length == size && value[^1] == 0);
        return Encoding.ASCII.GetString(value, 0, size - 1);
    }
    private static void Header(BinaryReader reader, byte[] reply, string method)
    {
        Require(reader.ReadUInt32() == reply.Length - 4 && Text(reader) == "MatchmakingProtocol");
        Require(reader.ReadByte() == 0 && reader.ReadByte() == 1 && reader.ReadUInt32() == 0x12345678);
        Require(Text(reader) == "MatchmakingProtocol::" + method + "_V1*");
    }
    private static uint Session(BinaryReader reader, ReadOnlySpan<byte> host)
    {
        uint id = reader.ReadUInt32(); Require(id != 0);
        Require(reader.ReadUInt32() == 0 && Text(reader) == "" && reader.ReadUInt64() == 0);
        Require(reader.ReadUInt32() == 0 && reader.ReadUInt32() == 0 && reader.ReadByte() == 0 && reader.ReadByte() == 0);
        Require(reader.ReadUInt32() == 1 && reader.ReadBytes(16).AsSpan().SequenceEqual(host) && reader.ReadUInt32() == 2);
        Require(reader.ReadUInt32() == 8);
        var texts = new Dictionary<string,string>();
        for (int i = 0; i < 8; ++i)
        {
            string key = Text(reader); byte tag = reader.ReadByte();
            if (tag == 4) texts.Add(key, Text(reader));
            else if (tag == 6) reader.ReadUInt64();
            else { Require(tag == 3 && key == "private"); Require(reader.ReadByte() == 0); }
        }
        Require(texts["settlers_session_name"] == "invented original title");
        Require(texts["settlers_map_name"] == "invented map");
        Require(reader.ReadUInt32() == 0);
        return id;
    }
    internal static int Run()
    {
        int checks = 0;
        void Check(bool result, string label) { ++checks; if (!result) throw new Exception(label); }
        using var a = RegisteredHostChecks.CreateRegistered();
        using var b = RegisteredHostChecks.CreateRegistered();
        a.TryCopyRegisteredPeer(out var hostA); b.TryCopyRegisteredPeer(out var hostB);
        using var lifetimeA = hostA; using var lifetimeB = hostB;
        using var registry = new LocalSessionRegistry();
        object ownerA = new(), ownerB = new(), viewer = new();
        Check(registry.TryCreate(ownerA, a, PublicBody(), out var idA, out _), "First host create");
        Check(registry.TryCreate(ownerB, b, PublicBody(), out var idB, out _), "Second host create");
        Check(LocalSessionCatalogueCodec.TrySearch(LocalSessionDisplayChecks.Search(), registry, viewer, out var reply, out _), "Public catalogue");
        using (var reader = new BinaryReader(new MemoryStream(reply)))
        {
            Header(reader, reply, "SearchSessions"); Require(reader.ReadUInt32() == 2);
            Require(Session(reader, hostA.ProfileId) == idA && Session(reader, hostB.ProfileId) == idB);
            Require(reader.ReadUInt32() == 2);
            Require(reader.ReadUInt32() == idA && Text(reader) == LocalSessionDisplayChecks.Route);
            Require(reader.ReadUInt32() == idB && Text(reader) == LocalSessionDisplayChecks.Route);
            Require(reader.BaseStream.Position == reader.BaseStream.Length); checks++;
        }
        // Either host discovers the other; self-owned sessions are excluded.
        foreach (var own in new[] { ownerA, ownerB })
        {
            Check(LocalSessionCatalogueCodec.TrySearch(LocalSessionDisplayChecks.Search(), registry, own, out reply, out _), "Other-host search");
            using var reader = new BinaryReader(new MemoryStream(reply)); Header(reader, reply, "SearchSessions");
            Check(reader.ReadUInt32() == 1, "Self-host row leaked");
            Check(Session(reader, ReferenceEquals(own, ownerA) ? hostB.ProfileId : hostA.ProfileId) ==
                (ReferenceEquals(own, ownerA) ? idB : idA), "Other-host identity mismatch");
        }
        foreach (var search in new[] { LocalSessionDisplayChecks.Search(limit: 0), LocalSessionDisplayChecks.Search(space: "other"),
            LocalSessionDisplayChecks.Search(filters: Map([.. Ddl("private"),3,1])),
            LocalSessionDisplayChecks.Search(filters: Map([.. Ddl("string4"),4,.. Ddl("Group")])) })
            Check(LocalSessionCatalogueCodec.TrySearch(search, registry, viewer, out reply, out _) &&
                reply.SequenceEqual(LocalSessionSearchChecks.EmptyResponse()), "Isolation filter ignored");
        Check(LocalSessionCatalogueCodec.TrySearch(LocalSessionDisplayChecks.Search(limit: 1), registry, viewer, out reply, out _)
            && BinaryPrimitives.ReadUInt32LittleEndian(reply.AsSpan(74)) == 1, "Result limit ignored");
        Check(!LocalSessionCatalogueCodec.TrySearch(LocalSessionDisplayChecks.Search(selector: "unknown"), registry, viewer, out _, out _), "Unknown selector");
        Check(!LocalSessionCatalogueCodec.TrySearch(LocalSessionDisplayChecks.Search(), registry, null, out _, out _), "Null requester");
        Check(!LocalSessionCatalogueCodec.TrySearch(LocalSessionDisplayChecks.Search(filters: Map([.. Ddl("search_score"),0])), registry, viewer, out _, out _), "Wrong ranking type");
        Check(LocalSessionCatalogueCodec.TrySearch(LocalSessionDisplayChecks.Search(filters: Map([.. Ddl("search_score"),1,0,0,0,0,0,0,0,0],
            [.. Ddl("private"),3,0])), registry, viewer, out reply, out _), "Supported ranking/public filter");
        byte[] get = Get(idB);
        Check(LocalSessionCatalogueCodec.TryGet(get, registry, ownerA, out reply, out _), "Get remote session");
        using (var reader = new BinaryReader(new MemoryStream(reply)))
        {
            Header(reader, reply, "GetSession"); Require(Session(reader, hostB.ProfileId) == idB);
            Check(reader.BaseStream.Position == reader.BaseStream.Length, "Get must have neither list count nor route map");
        }
        for (int length = 0; length < get.Length; ++length)
        {
            var truncated = get[..length];
            if (length >= 4) BinaryPrimitives.WriteUInt32LittleEndian(truncated, (uint)(length - 4));
            Check(!LocalSessionCatalogueCodec.TryGet(truncated, registry, viewer, out var invalid, out _) && invalid == null, "Truncated Get accepted");
        }
        Check(!LocalSessionCatalogueCodec.TryGet(Get(space: "other"), registry, viewer, out _, out _), "Get cross-space");
        Check(!LocalSessionCatalogueCodec.TryGet(Get(uint.MaxValue), registry, viewer, out _, out _), "Get unknown ID");
        Check(!LocalSessionCatalogueCodec.TryGet(get, registry, null, out _, out _), "Get null requester");
        registry.RemoveOwner(ownerB);
        Check(!LocalSessionCatalogueCodec.TryGet(get, registry, viewer, out _, out _), "Removed session still fetchable");
        Check(!registry.TryUpdate(ownerB, LocalSessionUpdateChecks.Body(), out _), "Other owner update");
        using var privateRegistry = new LocalSessionRegistry();
        Check(privateRegistry.TryCreate(ownerA, a, PublicBody(true), out _, out _), "Private setup");
        Check(LocalSessionCatalogueCodec.TrySearch(LocalSessionDisplayChecks.Search(), privateRegistry, viewer, out reply, out _)
            && reply.SequenceEqual(LocalSessionSearchChecks.EmptyResponse()), "Private session disclosed");
        Check(!LocalSessionCatalogueCodec.TryGet(Get(), privateRegistry, viewer, out _, out _), "Private Get disclosed");
        using var preview = new LocalSessionRegistry(true);
        Check(preview.TryCreate(ownerA, a, PublicBody(), out _, out _) && preview.TryLeave(ownerA, LocalSessionLeaveChecks.Body(), out _), "Preview setup");
        Check(!LocalSessionCatalogueCodec.TryGet(Get(), preview, viewer, out _, out _), "Retired preview fetchable");
        return checks + LocalLanCatalogueChecks.Run();
    }
}
