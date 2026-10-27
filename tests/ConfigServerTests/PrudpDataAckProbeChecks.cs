using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using S7Patcher.Source;

internal static class PrudpDataAckProbeChecks
{
    internal static async Task<int> RunAsync()
    {
        int passed = 0;
        void Check(bool condition, string message) { if (!condition) throw new Exception(message); passed++; }
        static void Sum(byte[] data)
        {
            uint sum = 0;
            for (int index = 0; index < data.Length - 4; index++)
                sum = unchecked(sum + ((uint)data[index] << ((index % 4) * 8)));
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(data.Length - 4), sum);
        }
        static byte[] Data(uint cookie, byte flags, byte[] payload, ushort sequence = 0x9abc, byte part = 0x7f)
        {
            bool sized = (flags & 0x40) != 0;
            byte[] packet = new byte[15 + (sized ? 2 : 0) + payload.Length];
            packet[0] = 0x3a; packet[1] = 0x31; packet[2] = (byte)(flags | 2); packet[3] = 0x53;
            BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(4), cookie);
            BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(8), sequence); packet[10] = part;
            if (sized) BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(11), (ushort)payload.Length);
            payload.CopyTo(packet, sized ? 13 : 11); Sum(packet); return packet;
        }
        byte[] fixedAck = PrudpDataAckProbeCodec.CreateReply(Data(0x11111111, 0x30, []), 0x56, 0x12345678);
        Check(fixedAck.SequenceEqual(new byte[] { 0x31, 0x3a, 0x0a, 0x56, 0x78, 0x56, 0x34, 0x12,
            0xbc, 0x9a, 0x7f, 0x65, 0x2b, 0xbe, 0x68 }), "Independent native-derived 15-byte DATA ACK fixture differs");
        ConcurrentQueue<ConfigServerEvent> events = new();
        TaskCompletionSource<ConfigServerEvent> ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource stop = new();
        Task service = LocalConfigurationServer.RunAsync(new() { HttpPort = 0, UdpPort = 0, DataAckProbe = true, Seconds = 20 }, item =>
        {
            events.Enqueue(item); if (item.Event == "configuration-server-ready") ready.TrySetResult(item);
        }, stop.Token);
        ConfigServerEvent info = await ready.Task.WaitAsync(TimeSpan.FromSeconds(4));
        using UdpClient sender = new(AddressFamily.InterNetwork);
        sender.Connect(IPAddress.Loopback, info.UdpPort!.Value);
        async Task<byte[]> Exchange(byte[] packet)
        {
            await sender.SendAsync(packet);
            using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(2));
            return (await sender.ReceiveAsync(deadline.Token)).Buffer;
        }
        async Task Silent(byte[] packet, UdpClient other = null)
        {
            UdpClient target = other ?? sender; await target.SendAsync(packet);
            using CancellationTokenSource deadline = new(TimeSpan.FromMilliseconds(100));
            try { await target.ReceiveAsync(deadline.Token); throw new Exception("Out-of-scope DATA received ACK"); }
            catch (OperationCanceledException) { passed++; }
        }
        try
        {
            await Silent(Data(0, 0x30, []));
            byte[] syn = new byte[18]; syn[0] = 0x3a; syn[1] = 0x31; syn[2] = 0x20; Sum(syn);
            byte[] synAck = await Exchange(syn);
            uint serverCookie = BinaryPrimitives.ReadUInt32LittleEndian(synAck.AsSpan(10));
            await Silent(Data(serverCookie, 0x30, [])); // SYN alone is not enough.
            using ECDiffieHellman client = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            ECParameters point = client.ExportParameters(false);
            byte[] connect = new byte[92];
            connect[0] = 0x3a; connect[1] = 0x31; connect[2] = 0xb1; connect[3] = 0x53;
            BinaryPrimitives.WriteUInt32LittleEndian(connect.AsSpan(4), serverCookie);
            BinaryPrimitives.WriteUInt16LittleEndian(connect.AsSpan(8), 0x1234);
            BinaryPrimitives.WriteUInt32LittleEndian(connect.AsSpan(10), 0x12345678);
            BinaryPrimitives.WriteUInt16LittleEndian(connect.AsSpan(14), 72);
            new byte[] { 0x45, 0x43, 0x4b, 0x31, 32, 0, 0, 0 }.CopyTo(connect, 16);
            point.Q.X!.CopyTo(connect, 24); point.Q.Y!.CopyTo(connect, 56); Sum(connect);
            Check(PrudpConnectProbe.TryReadRequest(connect, serverCookie, 0x3a, out var connectMetadata, out _), "Fixture CONNECT invalid");
            using (ECDsa signing = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            using (PrudpProbePeer unsent = new() { Cookie = serverCookie, SourceVirtualPort = 0x3a,
                SynReplySent = true, Connect = new PrudpConnectProbe(connect, connectMetadata, signing) })
            {
                Check(!PrudpDataAckProbeCodec.TryCreateReply(Data(serverCookie, 0x30, []), unsent, out _, out string reason)
                    && reason == "missing-connect-context", "Created CONNECT state without successful send permits DATA ACK");
            }
            byte[] connectAck = await Exchange(connect);
            Check(connectAck.Length == 158, "DATA ACK mode did not imply CONNECT probe");
            byte serverSession = connectAck[3];
            byte[] opaque = Encoding.ASCII.GetBytes("test-secret-opaque-data");
            foreach (byte flags in new byte[] { 0x20, 0x30, 0x60, 0x70 })
            {
                foreach (byte[] payload in new byte[][] { [], opaque })
                {
                    byte[] packet = Data(serverCookie, flags, payload);
                    byte[] ack = await Exchange(packet);
                    byte[] expected = (byte[])fixedAck.Clone(); expected[3] = serverSession; Sum(expected);
                    Check(ack.SequenceEqual(expected), "DATA ACK header/session/client-cookie/sequence/part or empty payload incorrect");
                    Check((await Exchange(packet)).SequenceEqual(ack), "DATA retry did not get same deterministic ACK");
                }
            }
            foreach ((ushort seq, byte part) in new (ushort, byte)[] { (0, 0), (65535, 255), (0x3579, 0x4f) })
            {
                byte[] ack = await Exchange(Data(serverCookie, 0x30, opaque, seq, part));
                Check(BinaryPrimitives.ReadUInt16LittleEndian(ack.AsSpan(8)) == seq && ack[10] == part,
                    "DATA sequence/part constrained to CONNECT or invented fragment rule");
            }
            foreach (byte flags in new byte[] { 0, 0x10, 0x08, 0x28, 0xa0, 0xb0, 0xe0, 0xf0 })
                await Silent(Data(serverCookie, flags, []));
            byte[] bad = Data(serverCookie, 0x30, opaque); bad[^1] ^= 1; await Silent(bad);
            foreach ((int offset, byte value) in new (int, byte)[] { (0, 0x3b), (1, 0x32), (3, 0x54) })
            {
                bad = Data(serverCookie, 0x30, opaque); bad[offset] = value; Sum(bad); await Silent(bad);
            }
            await Silent(Data(unchecked(serverCookie + 1), 0x30, opaque));
            await Silent([.. Data(serverCookie, 0x70, opaque), 1, 2, 3]);
            using UdpClient stranger = new(AddressFamily.InterNetwork);
            stranger.Connect(IPAddress.Loopback, info.UdpPort.Value);
            await Silent(Data(serverCookie, 0x30, opaque), stranger);
            Check((await Exchange(connect)).SequenceEqual(connectAck), "DATA ACK probe mutated the CONNECT retry context");
        }
        finally { stop.Cancel(); await service.WaitAsync(TimeSpan.FromSeconds(4)); }
        Check(events.Any(item => item.PacketType == "data" && item.KnownPeer == true && item.ConnectReplySent == true
            && item.RoutingMatches == true && item.ClientSessionMatches == true && item.HeaderCookieMatches == true),
            "Matching DATA context not reported as booleans");
        Check(events.Any(item => item.PacketType == "data" && item.KnownPeer == false && item.ConnectReplySent == false
            && item.RoutingMatches is null && item.ClientSessionMatches is null && item.HeaderCookieMatches is null),
            "Unknown peer fabricated context comparisons");
        Check(events.Any(item => item.PacketType == "data" && item.RoutingMatches == false), "Routing mismatch not observed");
        Check(events.Any(item => item.PacketType == "data" && item.ClientSessionMatches == false), "Session mismatch not observed");
        Check(events.Any(item => item.PacketType == "data" && item.HeaderCookieMatches == false), "Cookie mismatch not observed");
        Check(!events.Any(item => item.Event == "data-crypto-probe-observed"), "DATA ACK mode implicitly decrypted payloads");
        string[] allowed = ["event", "elapsed_milliseconds", "reason", "datagram_length", "authentication_implemented", "udp_protocol_implemented"];
        foreach (var item in events.Where(item => item.Event.StartsWith("data-ack-probe-")))
        {
            using JsonDocument log = JsonDocument.Parse(JsonSerializer.Serialize(item, ConfigServerJsonContext.Default.ConfigServerEvent));
            Check(log.RootElement.EnumerateObject().All(property => allowed.Contains(property.Name)), "DATA ACK logs expose packet fields");
            if (item.Event == "data-ack-probe-reply-sent")
                Check(item.DatagramLength == 15 && item.AuthenticationImplemented == false && item.UdpProtocolImplemented == false,
                    "DATA ACK event implies application acceptance");
        }
        Check(!string.Join("\n", events.Select(item => JsonSerializer.Serialize(item, ConfigServerJsonContext.Default.ConfigServerEvent)))
            .Contains("test-secret"), "DATA probe logged opaque payload");
        using (TcpListener rebound = new(IPAddress.Loopback, info.HttpPort!.Value))
        { rebound.Server.ExclusiveAddressUse = true; rebound.Start(); passed++; }
        using (UdpClient rebound = new(AddressFamily.InterNetwork))
        { rebound.Client.ExclusiveAddressUse = true; rebound.Client.Bind(new IPEndPoint(IPAddress.Loopback, info.UdpPort!.Value)); passed++; }
        return passed;
    }
}
