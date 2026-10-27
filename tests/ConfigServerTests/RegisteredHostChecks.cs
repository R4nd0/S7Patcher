using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using S7Patcher.Source;

internal static class RegisteredHostChecks
{
    private const string Auth = "prudp:/address=127.0.0.1;port=9111;stream=3;sid=1";
    private const string Candidate = "prudp:/address=192.0.2.9;port=1234;sid=10";
    private const string Observed = "prudp:/address=127.0.0.1;port=45678;sid=10";
    private static byte[] Ddl(string text) => LocalSessionSearchChecks.Ddl(text);
    private static byte[] Request(bool register, string url = Candidate)
    {
        byte[] body = register
            ? [0, 0, 0, 0, 1, 0, 0, 0, .. Ddl(url)]
            : [1, 0, 0, 0, .. Ddl("ClientVersionInfo"), 1, 0, .. Ddl("invented-token"), .. new byte[10], 0, .. Ddl("")];
        byte[] message = [0, 0, 0, 0, .. Ddl("LoginProtocol"), 1, 1, 0, 0, 0,
            .. Ddl("LoginProtocol::" + (register ? "Register_V1" : "LoginWithToken_V1")), .. body];
        BinaryPrimitives.WriteUInt32LittleEndian(message, (uint)(message.Length - 4));
        return message;
    }
    internal static LocalLoginRpcEngine CreateRegistered(IPAddress address = null, LocalNetworkPolicy network = null)
    {
        string auth = network == null ? Auth : "prudp:/address=" + network.BindAddress + ";port=9111;stream=3;sid=1";
        LocalLoginRpcEngine engine = new(0x3a, new(address ?? IPAddress.Loopback, 45678), auth, network);
        try
        {
            foreach (bool register in new[] { false, true })
            {
                if (!engine.TryHandle(Request(register), out var response, out _)) throw new Exception("Registration fixture failed");
                CryptographicOperations.ZeroMemory(response);
            }
            return engine;
        }
        catch { engine.Dispose(); throw; }
    }
    internal static int Run()
    {
        int passed = 0;
        void Check(bool value, string label) { if (!value) throw new Exception(label); passed++; }
        object owner = new(), other = new();
        byte[] body = LocalSessionCreationChecks.Body(); // Contains unrelated, claimed member GUIDs.
        using LocalSessionRegistry registry = new();
        using LocalLoginRpcEngine engine = new(0x3a, new(IPAddress.Loopback, 45678), Auth);
        Check(!engine.TryCopyRegisteredPeer(out var absent) && absent == null, "Unregistered identity exported");
        Check(!registry.TryCreate(owner, engine, body, out _, out _) && registry.Count == 0, "Unregistered host accepted");
        Check(!registry.TryCreate(owner, null, body, out _, out _) && registry.Count == 0, "Missing registration accepted");
        Check(engine.TryHandle(Request(false), out var login, out _), "Login failed");
        // Login response has exactly one raw GUID before its remaining output fields.
        int profileOffset = 4 + Ddl("LoginProtocol").Length + 2 + 4 + Ddl("LoginProtocol::LoginWithToken_V1*").Length;
        byte[] expectedProfile = login.AsSpan(profileOffset, 16).ToArray();
        CryptographicOperations.ZeroMemory(login);
        Check(!engine.TryCopyRegisteredPeer(out _) && !registry.TryCreate(owner, engine, body, out _, out _), "Login alone exported host");
        Check(!engine.TryHandle(Request(true, Candidate + ";custom=one|two"), out _, out _)
            && !engine.TryCopyRegisteredPeer(out _), "Catalogue URL delimiter accepted or failed registration published");
        Check(engine.TryHandle(Request(true), out var registered, out _), "Valid registration failed after rejection");
        int connectionOffset = 4 + Ddl("LoginProtocol").Length + 2 + 4 + Ddl("LoginProtocol::Register_V1*").Length;
        uint expectedConnection = BinaryPrimitives.ReadUInt32LittleEndian(registered.AsSpan(connectionOffset));
        CryptographicOperations.ZeroMemory(registered);
        Check(engine.TryCopyRegisteredPeer(out var identity), "Registered identity missing");
        using (identity)
        {
            Check(identity.ProfileId.SequenceEqual(expectedProfile) && identity.ConnectionId == expectedConnection
                && expectedConnection != 0 && identity.PublicUrl == Observed, "Identity differs from actual Login/Register response");
            Check(registry.TryCreate(owner, engine, body, out uint id, out _) && id == 1, "Registered create failed");
            Check(registry.TryGetHost(owner, id, out var stored), "Registry lost host");
            using (stored)
            {
                Check(stored.Matches(identity), "Registry substituted request-supplied identity/address");
                Check(!registry.TryGetHost(other, id, out _) && !registry.TryGetHost(owner, id + 1, out _), "Host lookup ignored owner or ID");
                using var different = CreateRegistered();
                Check(!registry.TryCreate(owner, different, body, out _, out var reason)
                    && reason == "local-session-owner-registration-mismatch" && registry.Count == 1, "Retry replaced registered host");
                Check(registry.TryUpdate(owner, LocalSessionUpdateChecks.Body(), out _), "Metadata update failed");
                Check(registry.TryGetHost(owner, id, out var afterUpdate), "Update lost host");
                using (afterUpdate) Check(afterUpdate.Matches(identity), "Metadata update changed host identity");
                ReadOnlySpan<byte> cleared = stored.ProfileId;
                stored.Dispose(); stored.Dispose();
                Check(cleared.IndexOfAnyExcept((byte)0) < 0 && stored.ConnectionId == 0 && stored.PublicUrl == null, "Snapshot disposal retained identity");
                Check(engine.TryCopyRegisteredPeer(out var stillRegistered), "Snapshot disposal affected engine");
                using (stillRegistered) Check(stillRegistered.Matches(identity), "Snapshot disposal changed original");
            }
            engine.Dispose();
            Check(!engine.TryCopyRegisteredPeer(out _), "Disposed engine exported registration");
            Check(registry.TryGetHost(owner, id, out var owned), "Registry retained borrowed engine buffer");
            using (owned)
            {
                Check(owned.Matches(identity), "Engine disposal changed registry snapshot");
                Check(registry.TryLeave(owner, LocalSessionLeaveChecks.Body(), out _)
                    && !registry.TryGetHost(owner, id, out _), "Leave retained host projection");
                Check(owned.Matches(identity), "Leave mutated caller-owned snapshot");
            }
        }
        foreach (bool removeOwner in new[] { false, true })
        {
            using var fresh = new LocalSessionRegistry();
            using var registration = CreateRegistered();
            Check(fresh.TryCreate(owner, registration, body, out uint id, out _), "Cleanup setup failed");
            if (removeOwner) fresh.RemoveOwner(owner); else fresh.Dispose();
            Check(!fresh.TryGetHost(owner, id, out _) && fresh.Count == 0, "Cleanup retained host record");
        }
        CryptographicOperations.ZeroMemory(expectedProfile);
        return passed;
    }
}
