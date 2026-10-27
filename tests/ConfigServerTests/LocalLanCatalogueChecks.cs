using System.Net;
using System.Text;
using S7Patcher.Source;

internal static class LocalLanCatalogueChecks
{
    internal static int Run()
    {
        int checks = 0;
        void Check(bool value, string label) { ++checks; if (!value) throw new Exception(label); }
        const string left = "192.168.10.10", right = "192.168.10.20";
        Check(LocalNetworkPolicy.TryCreate(left, right, out var network), "LAN catalogue policy fixture");
        foreach (bool reverse in new[] { false, true })
        {
            string address = reverse ? right : left, other = reverse ? left : right;
            using var host = RegisteredHostChecks.CreateRegistered(IPAddress.Parse(address), network);
            using var guest = RegisteredHostChecks.CreateRegistered(IPAddress.Parse(other), network);
            Check(host.TryCopyRegisteredPeer(out var peer), "LAN registered host fixture");
            using var peerLifetime = peer;
            foreach (bool foreignFirst in new[] { false, true })
            foreach (ushort port in new ushort[] { 3074, 6200, 9103 })
            {
                string owned = address + ":" + port;
                string foreign = "10.50.0.2:3074,127.0.0.1:3074," + other + ":3074";
                string routes = foreignFirst ? foreign + "," + owned : owned + "," + foreign;
                string original = LocalStormRouteChecks.Route(peer.ConnectionId, routes, emptyProfile:true, gatewaySentinel:true);
                string expected = LocalStormRouteChecks.Route(peer.ConnectionId, owned, emptyProfile:true, gatewaySentinel:true);
                using var registry = new LocalSessionRegistry(catalogueProbe:true);
                object owner = new(), viewer = new();
                Check(registry.TryCreate(owner, host, LocalSessionCatalogueChecks.PublicBody(route:original), out _, out _), "LAN create fixture");
                Check(LocalSessionCatalogueCodec.TrySearch(LocalSessionDisplayChecks.Search(), registry, viewer, out var search, out _),
                    "LAN search rejected owned route");
                string displayed = Encoding.ASCII.GetString(search);
                Check(displayed.Contains(expected, StringComparison.Ordinal) && search.AsSpan().EndsWith(LocalSessionSearchChecks.Ddl(expected))
                    && !displayed.Contains("10.50.0.2", StringComparison.Ordinal)
                    && !displayed.Contains("127.0.0.1:3074", StringComparison.Ordinal)
                    && !displayed.Contains(other + ":3074", StringComparison.Ordinal), "LAN catalogue exposed unrelated interface or changed native descriptor fields");
                Check(LocalSessionCatalogueCodec.TrySearch(LocalSessionDisplayChecks.Search(), registry, viewer, out var repeated, out _)
                    && repeated.SequenceEqual(search), "LAN projection is not stable");
                Check(registry.TryCopyLiveSession(viewer, "invented-space"u8, 1, out var snapshot), "LAN stored snapshot");
                using (snapshot) Check(Encoding.ASCII.GetString(snapshot.Metadata.Creation.StationUrls) == original,
                    "LAN discovery mutated original host metadata");
                Check(LocalSessionJoinCodec.TryReply(LocalSessionJoinChecks.Request(), registry, viewer, guest, out var join, out _), "LAN join projection");
                string joined = Encoding.ASCII.GetString(join);
                Check(joined.Contains(expected, StringComparison.Ordinal) && !joined.Contains(original, StringComparison.Ordinal),
                    "LAN search and join disagree on host game endpoint");
            }
            using var invalid = new LocalSessionRegistry(catalogueProbe:true);
            object invalidOwner = new(), invalidViewer = new();
            string wrong = LocalStormRouteChecks.Route(peer.ConnectionId, other + ":3074");
            Check(invalid.TryCreate(invalidOwner, host, LocalSessionCatalogueChecks.PublicBody(route:wrong), out _, out _), "LAN invalid route fixture");
            Check(!LocalSessionCatalogueCodec.TrySearch(LocalSessionDisplayChecks.Search(), invalid, invalidViewer, out var rejected, out var reason)
                && rejected == null && reason == "local-join-storm-no-owned-endpoint", "LAN discovery accepted foreign-only game route");
            Check(invalid.Count == 1, "Failed LAN discovery removed host session");
            string stale = LocalStormRouteChecks.Route(peer.ConnectionId ^ 1, address + ":3074");
            using var mismatch = new LocalSessionRegistry(catalogueProbe:true);
            Check(mismatch.TryCreate(new object(), host, LocalSessionCatalogueChecks.PublicBody(route:stale), out _, out _), "LAN connection mismatch fixture");
            Check(!LocalSessionCatalogueCodec.TrySearch(LocalSessionDisplayChecks.Search(), mismatch, new object(), out _, out reason)
                && reason == "local-join-storm-connection-mismatch", "LAN search bypassed registered connection ownership");
        }
        return checks;
    }
}
