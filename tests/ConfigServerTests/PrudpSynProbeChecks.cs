using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using S7Patcher.Source;

internal static class PrudpSynProbeChecks
{
    internal static async Task<int> RunAsync()
    {
        int passed = 0;
        void Check(bool condition, string message)
        {
            if (!condition) throw new Exception(message);
            passed++;
        }
        static void Checksum(byte[] data)
        {
            uint sum = 0;
            for (int index = 0; index < data.Length - 4; index++)
                sum = unchecked(sum + ((uint)data[index] << ((index % 4) * 8)));
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(data.Length - 4), sum);
        }
        // Invented fields; fixed known zero-seed checksum 0x73cb643e.
        byte[] syn = [0x3f, 0x31, 0x20, 0xa7, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0x3e, 0x64, 0xcb, 0x73];
        Check(PrudpSynProbeCodec.TryReadRequest(syn, out var request), "Known SYN request was rejected");
        byte[] fixedReply = PrudpSynProbeCodec.CreateReply(request, 0x12345678);
        Check(fixedReply.AsSpan(0, 14).SequenceEqual(new byte[] { 0x31, 0x3f, 8, 0, 0, 0, 0, 0,
            0x55, 0x66, 0x78, 0x56, 0x34, 0x12 }), "SYN-ACK serializer fields differ from native-derived layout");
        Check(BinaryPrimitives.ReadUInt32LittleEndian(fixedReply.AsSpan(14)) == 0x5680b7ba,
            "Fixed SYN-ACK checksum differs from independent word sum");
        try { PrudpSynProbeCodec.CreateReply(request, 0); throw new Exception("Zero cookie accepted"); }
        catch (ArgumentOutOfRangeException) { passed++; }

        ConcurrentQueue<ConfigServerEvent> events = new();
        TaskCompletionSource<ConfigServerEvent> ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource stop = new();
        Task service = LocalConfigurationServer.RunAsync(new() { HttpPort = 0, UdpPort = 0, SynProbe = true, Seconds = 15 }, item =>
        {
            events.Enqueue(item);
            if (item.Event == "configuration-server-ready") ready.TrySetResult(item);
        }, stop.Token);
        ConfigServerEvent info = await ready.Task.WaitAsync(TimeSpan.FromSeconds(4));
        List<UdpClient> senders = [];
        UdpClient Sender()
        {
            UdpClient sender = new(AddressFamily.InterNetwork);
            sender.Connect(IPAddress.Loopback, info.UdpPort!.Value);
            senders.Add(sender);
            return sender;
        }
        async Task<byte[]> Exchange(UdpClient sender, byte[] packet)
        {
            await sender.SendAsync(packet);
            using CancellationTokenSource limit = new(TimeSpan.FromSeconds(2));
            return (await sender.ReceiveAsync(limit.Token)).Buffer;
        }
        async Task Silent(UdpClient sender, byte[] packet)
        {
            await sender.SendAsync(packet);
            using CancellationTokenSource limit = new(TimeSpan.FromMilliseconds(100));
            try { await sender.ReceiveAsync(limit.Token); throw new Exception("Out-of-scope packet received a SYN reply"); }
            catch (OperationCanceledException) { passed++; }
        }
        try
        {
            UdpClient first = Sender();
            byte[] reply = await Exchange(first, syn);
            Check(reply.Length == 18 && reply[0] == 0x31 && reply[1] == 0x3f && reply[2] == 8 && reply[3] == 0,
                "Live SYN-ACK routing/flags/session incorrect");
            Check(BinaryPrimitives.ReadUInt32LittleEndian(reply.AsSpan(4)) == 0
                && BinaryPrimitives.ReadUInt16LittleEndian(reply.AsSpan(8)) == 0x6655, "Header signature/sequence incorrect");
            uint cookie = BinaryPrimitives.ReadUInt32LittleEndian(reply.AsSpan(10));
            Check(cookie != 0, "SYN probe generated zero cookie");
            uint expectedSum = unchecked(0x00083f31u + ((cookie << 16) | 0x6655u) + (cookie >> 16));
            Check(BinaryPrimitives.ReadUInt32LittleEndian(reply.AsSpan(14)) == expectedSum, "Live SYN-ACK checksum incorrect");
            Check((await Exchange(first, syn)).SequenceEqual(reply), "Retry changed its per-sender cookie");

            byte[] sized = [.. syn.AsSpan(0, 14).ToArray(), 0, 0, 0, 0, 0, 0];
            sized[2] = 0x60;
            Checksum(sized);
            Check((await Exchange(first, sized)).SequenceEqual(reply), "Optional zero payload length did not produce same ACK");
            byte[] bad = (byte[])syn.Clone();
            bad[14] ^= 1;
            await Silent(first, bad);
            foreach (byte flags in new byte[] { 0x28, 0x00, 0x30, 0xa0, 0x21 })
            {
                bad = (byte[])syn.Clone(); bad[2] = flags; Checksum(bad);
                await Silent(first, bad);
            }
            bad = (byte[])syn.Clone(); bad[0] = 0x2f; Checksum(bad); await Silent(first, bad);
            bad = (byte[])syn.Clone(); bad[1] = 0x32; Checksum(bad); await Silent(first, bad);
            bad = [.. syn.AsSpan(0, 14).ToArray(), 0x42, 0, 0, 0, 0]; Checksum(bad); await Silent(first, bad);
            await Silent(first, [.. sized, 1, 2, 3]);
            await Silent(first, reply); // ACKs cannot trigger a reply loop.

            for (int index = 1; index < 8; index++)
                Check((await Exchange(Sender(), syn)).Length == 18, "Allowed bounded sender was rejected");
            await Silent(Sender(), syn); // Ninth sender gets no cookie or reply.
            Check((await Exchange(first, syn)).SequenceEqual(reply), "Capacity limit evicted an existing sender's cookie");
        }
        finally
        {
            stop.Cancel();
            await service.WaitAsync(TimeSpan.FromSeconds(4));
            foreach (UdpClient sender in senders) sender.Dispose();
        }
        Check(events.Any(item => item.Event == "udp-datagram-observed" && item.PacketType == "syn"
            && item.ChecksumMatchesZeroSeed == true), "SYN mode did not imply passive metadata");
        string[] allowed = ["event", "elapsed_milliseconds", "datagram_length", "authentication_implemented", "udp_protocol_implemented"];
        foreach (ConfigServerEvent item in events.Where(item => item.Event == "syn-probe-reply-sent"))
        {
            using JsonDocument log = JsonDocument.Parse(JsonSerializer.Serialize(item, ConfigServerJsonContext.Default.ConfigServerEvent));
            Check(log.RootElement.EnumerateObject().All(property => allowed.Contains(property.Name)), "SYN reply log contains identifiers");
            Check(item.AuthenticationImplemented == false && item.UdpProtocolImplemented == false, "SYN reply claims a full protocol");
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
