using System;
using System.Net;
using S7Patcher.Source;

internal static class LocalNetworkPolicyChecks
{
    internal static int Run()
    {
        int count = 0;
        void Check(bool value) { if (!value) throw new Exception("Explicit network policy regression"); ++count; }
        Check(LocalNetworkPolicy.TryCreate("192.168.10.10", "192.168.10.20", out var policy));
        foreach (string address in new[] { "127.0.0.1", "192.168.10.10", "192.168.10.20" }) Check(policy.Allows(IPAddress.Parse(address)));
        foreach (string address in new[] { "192.168.10.21", "10.1.2.3", "8.8.8.8", "0.0.0.0", "::1", "::ffff:192.168.10.20" }) Check(!policy.Allows(IPAddress.Parse(address)));
        foreach (string address in new[] { "0.0.0.0", "127.0.0.1", "8.8.8.8", "192.168.10.0", "192.168.10.255", "192.168.010.20", "192.168.10.20 ", "3232238100", "localhost", "172.15.1.2", "172.32.1.2", "::ffff:192.168.10.20" })
            Check(!LocalNetworkPolicy.TryCreate("192.168.10.10", address, out _));
        Check(!LocalNetworkPolicy.TryCreate(null, "192.168.10.20", out _));
        Check(!LocalNetworkPolicy.TryCreate("192.168.10.10", "192.168.10.10", out _));
        foreach (string address in new[] { "10.1.2.3", "172.16.1.2", "172.31.1.2", "192.168.1.2" }) Check(LocalNetworkPolicy.TryPrivateAddress(address, out _));
        Check(!LocalNetworkPolicy.Loopback.Allows(IPAddress.Parse("192.168.10.20")));
        string auth = "prudp:/address=192.168.10.10;port=9111;sid=1;stream=3;type=2";
        using var engine = new LocalLoginRpcEngine(0x3a, new IPEndPoint(IPAddress.Parse("192.168.10.20"), 12345), auth, policy);
        Check(engine != null);
        foreach (string address in new[] { "192.168.10.21", "8.8.8.8" }) {
            bool rejected = false;
            try { using var invalid = new LocalLoginRpcEngine(0x3a, new IPEndPoint(IPAddress.Parse(address), 12345), auth, policy); }
            catch (ArgumentException) { rejected = true; }
            Check(rejected);
        }
        bool defaultRejected = false;
        try { using var invalid = new LocalLoginRpcEngine(0x3a, new IPEndPoint(IPAddress.Parse("192.168.10.20"), 12345), auth); }
        catch (ArgumentException) { defaultRejected = true; }
        Check(defaultRejected);
        return count;
    }
}
