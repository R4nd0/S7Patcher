using System.Text;
using System.Globalization;
using S7Patcher.Source;

internal static class LocalStormRouteChecks
{
    internal static string Route(uint connection, string endpoints = "127.0.0.1:3074", bool emptyProfile = false) =>
        "prudp:/RVCID=" + unchecked((int)connection).ToString(CultureInfo.InvariantCulture) + "#Storm=PeerGUID{InventedPeerNotAnIdentity}Version{1000000000000000001}"
        + "Platform{1}Gw{v(0)t(-)g()}Address{" + endpoints + "}PeerDescriptorBaseEnd{}"
        + "ProfileID{" + (emptyProfile ? "" : "00000000-0000-0000-0000-000000000077") + "}RoutingOption{32}";

    internal static int Run()
    {
        int passed = 0;
        void Check(bool b, string s) { if (!b) throw new Exception(s); passed++; }
        foreach (uint id in new uint[] { 1, 0x7fffffff, 0x80000000, 0xc0000001, 0xffffffff })
        {
            using var fixedPeer = new LocalLoginRpcEngine.RegisteredPeer(new byte[16], id, "prudp:/address=127.0.0.1;port=3074");
            string native = Route(id);
            string unsigned = "prudp:/RVCID=" + id.ToString(CultureInfo.InvariantCulture) + native[native.IndexOf('#')..];
            Check(LocalStormRoute.TryProject(native, fixedPeer, out var signedResult, out _) && signedResult == native, "Native signed RVCID rejected or changed");
            Check(LocalStormRoute.TryProject(unsigned, fixedPeer, out var unsignedResult, out _) && unsignedResult == unsigned, "Unsigned RVCID regression");
            using var wrongPeer = new LocalLoginRpcEngine.RegisteredPeer(new byte[16], id ^ 1, fixedPeer.PublicUrl);
            Check(!LocalStormRoute.TryProject(native, wrongPeer, out var denied, out var why) && denied == null
                && why == "local-join-storm-connection-mismatch", "Signed RVCID bypassed ownership");
            string empty = Route(id, emptyProfile:true);
            Check(LocalStormRoute.TryProject(empty, fixedPeer, out var emptyResult, out _) && emptyResult == empty,
                "Native empty ProfileID rejected or changed");
            Check(!LocalStormRoute.TryProject(empty, wrongPeer, out _, out _), "Empty ProfileID bypassed registered host identity");
            Check(!LocalStormRoute.TryProject(Route(id, "192.0.2.1:3074", emptyProfile:true), fixedPeer, out _, out _),
                "Empty ProfileID bypassed endpoint ownership");
            foreach (string invalidProfile in new[] { " ", "x", "-", "00000000000000000000000000000077" })
                Check(!LocalStormRoute.TryProject(empty.Replace("ProfileID{}", "ProfileID{" + invalidProfile + "}"), fixedPeer, out _, out _),
                    "Malformed nonempty ProfileID accepted");
            foreach (string invalid in new[] { "", "0", "-0", "+1", "01", "-01", "-2147483649", "4294967296", " 1", "1 ", "--1", "1.0", "0xffffffff" })
                Check(!LocalStormRoute.TryProject("prudp:/RVCID=" + invalid + native[native.IndexOf('#')..], fixedPeer, out _, out _), "Noncanonical or overflow RVCID accepted");
        }
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
            "prudp:/RVCID=0" + mixed[mixed.IndexOf('#')..], mixed + "|" + mixed,
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
