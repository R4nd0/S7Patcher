using System.Net;
using System.Net.NetworkInformation;
using S7Patcher.Source;

internal static class LocalPairRouteChecks
{
    internal static int Run()
    {
        int passed = 0;
        void Check(bool result) { if (!result) throw new Exception("Laboratory route boundary"); passed++; }
        string previous = Environment.GetEnvironmentVariable("S7_LOCAL_PAIR_ADDRESS");
        try
        {
            using var peer = new LocalLoginRpcEngine.RegisteredPeer(new byte[16], 42,
                "prudp:/address=127.0.0.2;port=45678");
            string source = LocalStormRouteChecks.Route(42, "192.0.2.1:3074");
            foreach (string value in new[] { null, "", "localhost", "127.0.0.2", "192.0.2.1", "8.8.8.8" })
            {
                Environment.SetEnvironmentVariable("S7_LOCAL_PAIR_ADDRESS", value);
                Check(!LocalStormRoute.TryProject(source, peer, out _, out _));
            }
            // Positive case uses an actual local adapter, never DNS or a remote endpoint.
            var address = NetworkInterface.GetAllNetworkInterfaces()
                .SelectMany(n => n.GetIPProperties().UnicastAddresses).Select(n => n.Address)
                .FirstOrDefault(a => LocalNetworkPolicy.TryPrivateAddress(a.ToString(), out _));
            if (address == null) { Console.WriteLine("SKIP local-pair NIC projection: no private adapter"); return passed; }
            Environment.SetEnvironmentVariable("S7_LOCAL_PAIR_ADDRESS", address.ToString());
            source = LocalStormRouteChecks.Route(42, address + ":3074");
#if S7_LOCAL_PAIR_LAB
            Check(LocalStormRoute.TryProject(source, peer, out var projected, out _)
                && projected == LocalStormRouteChecks.Route(42, "127.0.0.2:3074"));
            Check(LocalStormRoute.TryProject(projected, peer, out var again, out _) && again == projected);
            foreach (string endpoints in new[] { address + ":3074,127.0.0.2:3074", "127.0.0.2:3074," + address + ":3074" })
                Check(LocalStormRoute.TryProject(LocalStormRouteChecks.Route(42, endpoints), peer, out var result, out _)
                    && result == projected);
            using var second = new LocalLoginRpcEngine.RegisteredPeer(new byte[16], 42,
                "prudp:/address=127.0.0.3;port=45679");
            Check(LocalStormRoute.TryProject(source, second, out var right, out _)
                && right == LocalStormRouteChecks.Route(42, "127.0.0.3:3074"));
            Check(!LocalStormRoute.IsLabLoopbackProjection(IPAddress.Parse("192.0.2.1"), address));
            Check(!LocalStormRoute.IsLabLoopbackProjection(IPAddress.IPv6Loopback, address));
            Check(!LocalStormRoute.IsLabLoopbackProjection(null, address));
            Check(!LocalStormRoute.IsLabLoopbackProjection(IPAddress.Loopback, null));
            Check(!LocalStormRoute.IsLabLoopbackProjection(IPAddress.Loopback, IPAddress.Parse("192.0.2.1")));
            Environment.SetEnvironmentVariable("S7_LOCAL_PAIR_ADDRESS", null);
            Check(!LocalStormRoute.TryProject(source, peer, out _, out _));
#else
            // Setting the laboratory environment flag cannot enable it in production.
            Check(!LocalStormRoute.TryProject(source, peer, out _, out _));
#endif
            return passed;
        }
        finally { Environment.SetEnvironmentVariable("S7_LOCAL_PAIR_ADDRESS", previous); }
    }
}
