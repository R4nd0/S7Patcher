using System.Text;
using S7Patcher.Source;

internal static class LocalStormRouteChecks
{
    internal static string Route(uint connection, string endpoints = "127.0.0.1:3074") =>
        "prudp:/RVCID=" + connection + "#Storm=PeerGUID{InventedPeerNotAnIdentity}Version{1000000000000000001}"
        + "Platform{1}Gw{v(0)t(-)g()}Address{" + endpoints + "}PeerDescriptorBaseEnd{}"
        + "ProfileID{00000000-0000-0000-0000-000000000077}RoutingOption{32}";

    internal static int Run()
    {
        int passed = 0;
        void Check(bool b, string s) { if (!b) throw new Exception(s); passed++; }
        using var host = RegisteredHostChecks.CreateRegistered();
        using var guest = RegisteredHostChecks.CreateRegistered();
        host.TryCopyRegisteredPeer(out var peer);
        using var hp = peer;
        string mixed = Route(hp.ConnectionId, "192.0.2.1:3074,127.0.0.1:3074,10.0.0.1:3074");
        string expected = Route(hp.ConnectionId);
        Check(LocalStormRoute.TryProject(mixed, hp, out var projection, out _) && projection == expected, "Storm ownership projection");
        Check(LocalStormRoute.TryProject(projection, hp, out var repeated, out _) && repeated == projection, "Storm projection not idempotent");
        Check(!LocalStormRoute.TryProject(Route(hp.ConnectionId, "192.0.2.1:3074"), hp, out _, out var reason)
            && reason == "local-join-storm-no-owned-endpoint", "Foreign-only endpoints accepted");
        foreach (string bad in new[] {
            mixed.Replace("RVCID=" + hp.ConnectionId, "RVCID=0"), mixed + "|" + mixed,
            mixed.Replace("#Storm=", "#Other="), mixed.Replace("#Storm=", ";port=3074#Storm="),
            mixed.Replace("Address{", "Address{{"), mixed.Replace("RoutingOption{32}", "RoutingOption{32}Address{127.0.0.1:3074}"),
            mixed.Replace("Gw{v(0)t(-)g()}", "Gw{v(0)t(-)g(example.com)}"),
            mixed.Replace("PeerDescriptorBaseEnd{}", "PeerDescriptorBaseEnd{x}"), mixed.Replace("Platform{1}", "Platform{-1}"),
            mixed.Replace("RoutingOption{32}", "RoutingOption{4294967296}"),
            mixed.Replace("1000000000000000001", "18446744073709551616"), mixed.Replace("00000000-0000", "invalid-0000"),
            mixed.Replace("InventedPeerNotAnIdentity", "x;redirected=1"), mixed.Replace("InventedPeerNotAnIdentity", "x#Storm=y"),
            mixed.Replace("InventedPeerNotAnIdentity", "x\0y"), mixed.Replace("InventedPeerNotAnIdentity", "x\ny"),
            mixed.Replace("InventedPeerNotAnIdentity", "x%20y"), mixed.Replace("InventedPeerNotAnIdentity", "x y"),
            mixed.Replace("127.0.0.1:3074", "127.0.0.1:0"), mixed.Replace("127.0.0.1:3074", "127.1:3074"),
            mixed.Replace("127.0.0.1:3074", "127.0.0.1:03074"), mixed.Replace("127.0.0.1:3074", "127.0.0.1:65536"),
            mixed.Replace("127.0.0.1:3074", "[::1]:3074"), mixed.Replace("127.0.0.1:3074", "127.0.0.1:3074,127.0.0.1:3074"),
            mixed + "trailing", new string('x', 2049) })
            Check(!LocalStormRoute.TryProject(bad, hp, out var output, out _) && output == null, "Malformed Storm route accepted");
        for (int i = 0; i < mixed.Length; i++) Check(!LocalStormRoute.TryProject(mixed[..i], hp, out _, out _), "Truncated descriptor accepted");
        Check(!LocalStormRoute.TryProject(Route(hp.ConnectionId, string.Join(',', Enumerable.Range(1,17).Select(i => "10.0.0."+i+":3074"))), hp, out _, out _), "Endpoint cap missing");
        object owner = new(), visitor = new();
        using var registry = new LocalSessionRegistry(catalogueProbe:true);
        Check(registry.TryCreate(owner, host, LocalSessionCatalogueChecks.PublicBody(route:mixed), out _, out _), "Storm create fixture");
        Check(LocalSessionJoinCodec.TryReply(LocalSessionJoinChecks.Request(), registry, visitor, guest, out var response, out _), "Storm join rejected");
        using (var reader = new BinaryReader(new MemoryStream(response)))
        {
            string Text() { int n=reader.ReadUInt16(); return Encoding.ASCII.GetString(reader.ReadBytes(n)[..^1]); }
            reader.ReadUInt32(); Text(); reader.ReadUInt16(); reader.ReadUInt32(); Text();
            Check(Text()==expected, "Join returned unfiltered Storm endpoints");
        }
        Check(registry.TryCopyLiveSession(visitor, "invented-space"u8, 1, out var snapshot), "Storm snapshot missing");
        using(snapshot) Check(Encoding.ASCII.GetString(snapshot.Metadata.Creation.StationUrls)==mixed, "Projection mutated host source");
        Check(LocalSessionJoinCodec.TryReply(LocalSessionJoinChecks.Request(), registry, visitor, guest, out var replay, out _)
            && response.SequenceEqual(replay), "Storm join replay changed projection");
        return passed;
    }
}
