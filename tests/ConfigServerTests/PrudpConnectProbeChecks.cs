using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using S7Patcher.Source;

internal static class PrudpConnectProbeChecks
{
    internal static async Task<int> RunAsync()
    {
        int passed = 0;
        void Check(bool condition, string message)
        {
            if (!condition) throw new Exception(message);
            passed++;
        }
        static void Sum(byte[] data)
        {
            uint sum = 0;
            for (int index = 0; index < data.Length - 4; index++)
                sum = unchecked(sum + ((uint)data[index] << ((index % 4) * 8)));
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(data.Length - 4), sum);
        }
        static byte[] Public(ECDiffieHellman key)
        {
            ECParameters point = key.ExportParameters(false);
            return [0x45, 0x43, 0x4b, 0x31, 32, 0, 0, 0, .. point.Q.X!, .. point.Q.Y!];
        }
        static byte[] Request(uint cookie, byte[] publicKey, bool sized = false)
        {
            byte[] packet = new byte[20 + publicKey.Length + (sized ? 2 : 0)];
            packet[0] = 0x3f; packet[1] = 0x31; packet[2] = sized ? (byte)0xf1 : (byte)0xb1; packet[3] = 0x53;
            BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(4), cookie);
            BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(8), 0x1243);
            BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(10), 0x87654321);
            BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(14), (ushort)publicKey.Length);
            publicKey.CopyTo(packet, 16);
            Sum(packet);
            return packet;
        }
        ConcurrentQueue<ConfigServerEvent> events = new();
        TaskCompletionSource<ConfigServerEvent> ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource stop = new();
        Task service = LocalConfigurationServer.RunAsync(new() { HttpPort = 0, UdpPort = 0, ConnectProbe = true, Seconds = 20 }, item =>
        {
            events.Enqueue(item);
            if (item.Event == "configuration-server-ready") ready.TrySetResult(item);
        }, stop.Token);
        ConfigServerEvent info = await ready.Task.WaitAsync(TimeSpan.FromSeconds(4));
        using UdpClient sender = new(AddressFamily.InterNetwork);
        sender.Connect(IPAddress.Loopback, info.UdpPort!.Value);
        async Task<byte[]> Exchange(byte[] packet)
        {
            await sender.SendAsync(packet);
            using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(2));
            return (await sender.ReceiveAsync(timeout.Token)).Buffer;
        }
        async Task Silent(byte[] packet, UdpClient other = null)
        {
            UdpClient target = other ?? sender;
            await target.SendAsync(packet);
            using CancellationTokenSource timeout = new(TimeSpan.FromMilliseconds(100));
            try { await target.ReceiveAsync(timeout.Token); throw new Exception("Rejected CONNECT/DATA produced a response"); }
            catch (OperationCanceledException) { passed++; }
        }
        try
        {
            using HttpClient http = new(new HttpClientHandler { UseProxy = false });
            using JsonDocument config = JsonDocument.Parse(await http.GetStringAsync($"http://127.0.0.1:{info.HttpPort}{LocalConfigurationServer.ConfigurationPath}"));
            byte[] trust = Convert.FromBase64String(config.RootElement.GetProperty("public_key").GetString()!);
            using ECDiffieHellman client = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            byte[] clientBlob = Public(client);
            await Silent(Request(0x1234, clientBlob)); // No SYN context yet.
            byte[] syn = [0x3f, 0x31, 0x20, 0xa7, 0x11, 0x22, 0x33, 0x44,
                0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0x3e, 0x64, 0xcb, 0x73];
            byte[] synReply = await Exchange(syn);
            Check(synReply.Length == 18, "CONNECT mode did not imply SYN probe");
            uint serverCookie = BinaryPrimitives.ReadUInt32LittleEndian(synReply.AsSpan(10));
            byte[] request = Request(serverCookie, clientBlob);
            Check(request.Length == 92 && PrudpConnectProbe.TryReadRequest(request, serverCookie, 0x3f, out _, out _),
                "Valid empty CONNECT request rejected");
            byte[] bad = (byte[])request.Clone(); bad[^1] ^= 1; await Silent(bad);
            foreach ((int offset, byte replacement) in new (int, byte)[] { (0, 0x3e), (1, 0x32), (2, 0x31), (3, 0) })
            {
                bad = (byte[])request.Clone(); bad[offset] = replacement; Sum(bad); await Silent(bad);
            }
            await Silent(Request(unchecked(serverCookie + 1), clientBlob));
            byte[] malformed = (byte[])clientBlob.Clone(); malformed[0] = 0x44; await Silent(Request(serverCookie, malformed));
            malformed = (byte[])clientBlob.Clone(); malformed[4] = 31; await Silent(Request(serverCookie, malformed));
            malformed = (byte[])clientBlob.Clone(); Array.Clear(malformed, 8, 64);
            Check(!PrudpConnectProbe.TryReadRequest(Request(serverCookie, malformed), serverCookie, 0x3f, out _, out _),
                "Off-curve public point accepted by crypto guard");
            await Silent(Request(serverCookie, malformed));
            await Silent(Request(serverCookie, clientBlob[..71]));
            bad = [.. request.AsSpan(0, request.Length - 4).ToArray(), 0x42, 0, 0, 0, 0]; Sum(bad); await Silent(bad);
            await Silent([.. Request(serverCookie, clientBlob, true), 0x11]);

            byte[] reply = await Exchange(request);
            Check(reply.Length == 158 && reply[0] == 0x31 && reply[1] == 0x3f && reply[2] == 0x89 && reply[3] != 0,
                "CONNECT ACK routing/type/server session incorrect");
            Check(BinaryPrimitives.ReadUInt32LittleEndian(reply.AsSpan(4)) == 0x87654321
                && BinaryPrimitives.ReadUInt16LittleEndian(reply.AsSpan(8)) == 0x1243
                && BinaryPrimitives.ReadUInt32LittleEndian(reply.AsSpan(10)) == 0,
                "CONNECT ACK confused client/server cookies, sequence or ACK connection signature");
            Check(BinaryPrimitives.ReadUInt16LittleEndian(reply.AsSpan(14)) == 64
                && BinaryPrimitives.ReadUInt16LittleEndian(reply.AsSpan(80)) == 72, "CONNECT ACK crypto lengths incorrect");
            byte[] signature = reply.AsSpan(16, 64).ToArray();
            byte[] serverBlob = reply.AsSpan(82, 72).ToArray();
            Check(serverBlob.AsSpan(0, 8).SequenceEqual(new byte[] { 0x45, 0x43, 0x4b, 0x31, 32, 0, 0, 0 }),
                "Agreement key is not ECK1 P-256");
            Check(!serverBlob.AsSpan(8).SequenceEqual(trust.AsSpan(8)), "Agreement key reused the configuration signing key");
            byte[] summed = (byte[])reply.Clone(); Sum(summed);
            Check(summed.SequenceEqual(reply), "CONNECT ACK checksum differs from independent byte sum");
            if (OperatingSystem.IsWindows())
            {
                using CngKey nativeTrust = CngKey.Import(trust, CngKeyBlobFormat.EccPublicBlob);
                using ECDsaCng verifier = new(nativeTrust);
                Check(verifier.VerifyData(serverBlob, signature, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation), "Native CNG rejected signature under actual HTTP trust anchor");
                byte[] changed = (byte[])serverBlob.Clone(); changed[8] ^= 1;
                Check(!verifier.VerifyData(changed, signature, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation), "Signature did not cover complete server key blob");
                using CngKey nativeAgreement = CngKey.Import(serverBlob, CngKeyBlobFormat.EccPublicBlob);
                Check(nativeAgreement.KeySize == 256 && nativeAgreement.AlgorithmGroup == CngAlgorithmGroup.ECDiffieHellman,
                    "Native CNG did not import the ECK1 agreement key");
                using ECDiffieHellmanCng peer = new(nativeAgreement);
                Check(client.DeriveKeyFromHash(peer.PublicKey, HashAlgorithmName.SHA1).Length == 20,
                    "Native imported public key cannot participate in ECDH");
            }
            else
            {
                using ECDsa verifier = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint { X = trust.AsSpan(8, 32).ToArray(), Y = trust.AsSpan(40, 32).ToArray() } });
                Check(verifier.VerifyData(serverBlob, signature, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation), "Signature invalid under HTTP trust anchor");
            }
            Check((await Exchange(request)).SequenceEqual(reply), "CONNECT retry changed cached response bytes");
            Check((await Exchange(Request(serverCookie, clientBlob, true))).SequenceEqual(reply), "Sized retry changed response");
            foreach (int offset in new[] { 3, 8, 10 })
            {
                bad = (byte[])request.Clone(); bad[offset] ^= 1; Sum(bad); await Silent(bad);
            }
            using ECDiffieHellman otherKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            await Silent(Request(serverCookie, Public(otherKey)));
            using UdpClient otherSender = new(AddressFamily.InterNetwork);
            otherSender.Connect(IPAddress.Loopback, info.UdpPort.Value);
            await Silent(request, otherSender);
            await Silent(reply); // ACK never triggers another ACK.
            bad = (byte[])syn.Clone(); bad[2] = 2; Sum(bad); await Silent(bad); // DATA stays unimplemented.
            Check((await Exchange(request)).SequenceEqual(reply), "Rejected packets altered connection state");
        }
        finally
        {
            stop.Cancel();
            await service.WaitAsync(TimeSpan.FromSeconds(4));
        }
        Check(events.Any(item => item.Event == "connect-probe-request-rejected" && item.Reason == "nonempty-payload"),
            "Unsupported payload needs a fixed diagnostic reason");
        Check(events.Any(item => item.Event == "udp-datagram-observed" && item.PacketType == "data"),
            "CONNECT mode did not passively classify subsequent DATA");
        string[] allowed = ["event", "reason", "datagram_length", "authentication_implemented", "udp_protocol_implemented"];
        foreach (ConfigServerEvent item in events.Where(item => item.Event.StartsWith("connect-probe-")))
        {
            using JsonDocument log = JsonDocument.Parse(JsonSerializer.Serialize(item, ConfigServerJsonContext.Default.ConfigServerEvent));
            Check(log.RootElement.EnumerateObject().All(property => allowed.Contains(property.Name)), "CONNECT log contains identifiers or crypto values");
            if (item.Event == "connect-probe-reply-sent")
                Check(item.AuthenticationImplemented == false && item.UdpProtocolImplemented == false, "CONNECT reply claims authentication");
        }
        using (TcpListener rebound = new(IPAddress.Loopback, info.HttpPort!.Value))
        {
            rebound.Server.ExclusiveAddressUse = true; rebound.Start(); passed++;
        }
        using (UdpClient rebound = new(AddressFamily.InterNetwork))
        {
            rebound.Client.ExclusiveAddressUse = true;
            rebound.Client.Bind(new IPEndPoint(IPAddress.Loopback, info.UdpPort!.Value)); passed++;
        }
        return passed;
    }
}
