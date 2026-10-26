using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using S7Patcher.Source;

internal static class LocalLoginSessionChecks
{
    private const uint ServerCookie = 0x7abc1234, ClientCookie = 0x1234abcd;
    private const byte ClientSession = 0x53;
    private const ushort ConnectSequence = 5;
    private const string PublicUrl = "prudp:/address=198.51.100.7;port=40000;sid=10";

    private static void Sum(byte[] packet)
    {
        uint sum = 0;
        for (int index = 0; index < packet.Length - 4; index++)
            sum = unchecked(sum + ((uint)packet[index] << ((index % 4) * 8)));
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(packet.Length - 4), sum);
    }
    private static byte[] Ddl(string value)
    {
        byte[] result = new byte[value.Length + 3];
        BinaryPrimitives.WriteUInt16LittleEndian(result, (ushort)(value.Length + 1));
        Encoding.ASCII.GetBytes(value, result.AsSpan(2)); return result;
    }
    private static byte[] Request(bool register, uint callId = 0x456789ab)
    {
        byte[] body = register
            ? [0, 0, 0, 0, 1, 0, 0, 0, .. Ddl(PublicUrl)]
            : [1, 0, 0, 0, .. Ddl("ClientVersionInfo"), 1, 0,
                .. Ddl("test-secret-invented-token"), .. new byte[10], 0, .. Ddl("prudp:/")];
        byte[] id = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(id, callId);
        byte[] result = [0, 0, 0, 0, .. Ddl("LoginProtocol"), 1, .. id,
            .. Ddl(register ? "LoginProtocol::Register_V1" : "LoginProtocol::LoginWithToken_V1"), .. body];
        BinaryPrimitives.WriteUInt32LittleEndian(result, (uint)(result.Length - 4)); return result;
    }
    private static byte[] Connect(uint cookie, ECDiffieHellman client)
    {
        ECParameters point = client.ExportParameters(false);
        byte[] packet = new byte[92]; packet[0] = 0x3a; packet[1] = 0x31; packet[2] = 0xb1; packet[3] = ClientSession;
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(4), cookie);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(8), ConnectSequence);
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(10), ClientCookie);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(14), 72);
        new byte[] { 0x45, 0x43, 0x4b, 0x31, 32, 0, 0, 0 }.CopyTo(packet, 16);
        point.Q.X!.CopyTo(packet, 24); point.Q.Y!.CopyTo(packet, 56); Sum(packet); return packet;
    }
    private static byte[] Data(uint cookie, byte[] key, ushort sequence, byte part, ReadOnlySpan<byte> plaintext)
    {
        byte[] extended = new byte[plaintext.Length + 3]; plaintext.CopyTo(extended.AsSpan(1));
        BinaryPrimitives.WriteUInt16LittleEndian(extended.AsSpan(extended.Length - 2), sequence);
        byte[] iv = Enumerable.Range(0, 16).Select(index => (byte)(index + 1)).ToArray();
        byte[] body = [.. iv, .. NativeCngFixtures.Encrypt(extended, key, iv)];
        byte[] packet = new byte[body.Length + 15];
        packet[0] = 0x3a; packet[1] = 0x31; packet[2] = 0x32; packet[3] = ClientSession;
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(4), cookie);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(8), sequence); packet[10] = part;
        body.CopyTo(packet, 11); Sum(packet); CryptographicOperations.ZeroMemory(extended); return packet;
    }
    private static byte[] Ack(uint cookie, ushort sequence, bool explicitLength = false)
    {
        byte[] packet = new byte[explicitLength ? 17 : 15];
        packet[0] = 0x3a; packet[1] = 0x31; packet[2] = explicitLength ? (byte)0x4a : (byte)0x0a; packet[3] = ClientSession;
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(4), cookie);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(8), sequence); Sum(packet); return packet;
    }
    private static byte[] Ping(uint cookie = ServerCookie, byte flags = 0x20, ushort sequence = 12)
    {
        byte[] packet = new byte[(flags & 0x40) != 0 ? 16 : 14];
        packet[0] = 0x3a; packet[1] = 0x31; packet[2] = (byte)(4 | flags); packet[3] = ClientSession;
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(4), cookie);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(8), sequence); Sum(packet); return packet;
    }
    private static byte[] DecodeResponse(byte[] packet, byte[] key, uint callId, bool register,
        byte serverSession, int authenticationPort = 9111, int publicPort = 40000)
    {
        if (!PrudpDataPacketDecoder.TryDecode(packet, out var data, out _, 0) || data.BytesConsumed != packet.Length
            || packet[0] != 0x31 || packet[1] != 0x3a || packet[2] != 0x32 || packet[3] != serverSession || serverSession == 0 || packet[10] != 0
            || BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(4)) != ClientCookie)
            throw new Exception("Invalid server DATA frame");
        byte[] envelope = NativeCngFixtures.Decrypt(packet.AsSpan(27, data.PayloadLength - 16).ToArray(), key, packet.AsSpan(11, 16).ToArray());
        byte[] expanded = null;
        try
        {
            if (envelope[0] == 0) expanded = envelope.AsSpan(1).ToArray();
            else
            {
                using MemoryStream input = new(envelope, 1, envelope.Length - 1, false);
                using ZLibStream zlib = new(input, CompressionMode.Decompress);
                using MemoryStream output = new(); zlib.CopyTo(output); expanded = output.ToArray();
            }
            if (expanded.Length < 2 || BinaryPrimitives.ReadUInt16LittleEndian(expanded.AsSpan(expanded.Length - 2))
                != BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(8))) throw new Exception("Wrong response crypto sequence");
            ReadOnlySpan<byte> message = expanded.AsSpan(0, expanded.Length - 2);
            if (BinaryPrimitives.ReadUInt32LittleEndian(message) != message.Length - 4) throw new Exception("Wrong response message length");
            int offset = 4;
            string ReadDdl()
            {
                int size = BinaryPrimitives.ReadUInt16LittleEndian(expanded.AsSpan(offset)); offset += 2;
                if (size < 1 || size > expanded.Length - 2 - offset || expanded[offset + size - 1] != 0) throw new Exception("Wrong response DDL");
                string value = Encoding.ASCII.GetString(expanded, offset, size - 1); offset += size; return value;
            }
            bool HasParameter(string url, string name, string value) => url.StartsWith("prudp:/", StringComparison.Ordinal)
                && url[7..].Split(';').Count(pair => pair == name + "=" + value) == 1;
            if (ReadDdl() != "LoginProtocol" || expanded[offset++] != 0 || expanded[offset++] != 1
                || BinaryPrimitives.ReadUInt32LittleEndian(expanded.AsSpan(offset)) != callId) throw new Exception("Wrong response envelope");
            offset += 4;
            if (ReadDdl() != (register ? "LoginProtocol::Register_V1*" : "LoginProtocol::LoginWithToken_V1*")) throw new Exception("Wrong response method");
            if (register)
            {
                if (BinaryPrimitives.ReadUInt32LittleEndian(expanded.AsSpan(offset)) == 0) throw new Exception("Zero local RVCID");
                offset += 4; string url = ReadDdl();
                if (!HasParameter(url, "address", "127.0.0.1") || !HasParameter(url, "port", publicPort.ToString())
                    || !HasParameter(url, "sid", "10") || url.Contains("198.51.100.7")) throw new Exception("Register URL did not use observed peer");
            }
            else
            {
                if (expanded.AsSpan(offset, 16).SequenceEqual(new byte[16])) throw new Exception("Zero local profile");
                offset += 16; string url = ReadDdl();
                if (!HasParameter(url, "address", "127.0.0.1") || !HasParameter(url, "port", authenticationPort.ToString())
                    || !HasParameter(url, "sid", "1") || !url.Contains("DID=")) throw new Exception("Missing local auth endpoint");
                if (expanded[offset++] != 0) throw new Exception("Unexpected redirect");
            }
            if (offset != message.Length) throw new Exception("Response body not fully consumed");
            return message.ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(envelope); if (expanded != null) CryptographicOperations.ZeroMemory(expanded); }
    }
    private sealed class Fixture : IDisposable
    {
        internal readonly PrudpProbePeer Peer;
        internal readonly PrudpLocalLoginSession Session;
        internal readonly byte[] Key;
        internal readonly byte ServerSession;
        internal readonly List<ConfigServerEvent> Events = new();
        internal Fixture(long now = 100, bool keepAlive = false)
        {
            using ECDiffieHellman client = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            using ECDsa signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            byte[] packet = Connect(ServerCookie, client);
            if (!PrudpConnectProbe.TryReadRequest(packet, ServerCookie, 0x3a, out var request, out _)) throw new Exception("Invalid synthetic CONNECT");
            Peer = new() { Cookie = ServerCookie, SourceVirtualPort = 0x3a, SynReplySent = true, ConnectReplySent = true,
                Connect = new PrudpConnectProbe(packet, request, signer) };
            Peer.Connect.TryGetReply(packet, request, out byte[] reply);
            ServerSession = reply[3];
            Key = NativeCngFixtures.Derive(client, reply.AsSpan(82, 72).ToArray());
            Session = new(Peer, new(IPAddress.Loopback, 40000), "prudp:/address=127.0.0.1;port=9111;sid=1;stream=3;type=2", now, keepAlive);
        }
        internal byte[] Data(ushort sequence, byte part, ReadOnlySpan<byte> content) => LocalLoginSessionChecks.Data(ServerCookie, Key, sequence, part, content);
        internal void Login() => Session.ProcessData(Data(6, 0, Request(false)), Events.Add);
        internal void Register()
        {
            Login(); Session.TakeDue(100, Events.Add); Session.TryAcknowledge(Ack(ServerCookie, 1));
            Session.ProcessData(Data(7, 0, Request(true)), Events.Add);
            Session.TakeDue(100, Events.Add); Session.TryAcknowledge(Ack(ServerCookie, 2));
        }
        public void Dispose() { Session.Dispose(); Peer.Dispose(); CryptographicOperations.ZeroMemory(Key); }
    }

    internal static int Run()
    {
        if (!OperatingSystem.IsWindows()) { Console.WriteLine("SKIP: native BCrypt local-login session checks require Windows."); return 0; }
        int passed = 0;
        void Check(bool value, string label) { if (!value) throw new Exception(label); passed++; }
        using (Fixture fixture = new())
        {
            Check(!PrudpPingAckCodec.TryCreateReply(Ping(), null, out _), "Unknown PING peer accepted");
            foreach (byte flags in new byte[] { 0x20, 0x60 })
            {
                Check(PrudpPingAckCodec.TryCreateReply(Ping(flags: flags), fixture.Peer, out byte[] reply)
                    && reply.Length == 14 && reply[0] == 0x31 && reply[1] == 0x3a && reply[2] == 0x0c
                    && reply[3] == fixture.ServerSession
                    && BinaryPrimitives.ReadUInt32LittleEndian(reply.AsSpan(4)) == ClientCookie
                    && BinaryPrimitives.ReadUInt16LittleEndian(reply.AsSpan(8)) == 12,
                    "PING ACK context or sequence differs");
                byte[] checksum = (byte[])reply.Clone(); Sum(checksum);
                Check(checksum.SequenceEqual(reply), "PING ACK checksum differs from independent oracle");
                PrudpPingAckCodec.TryCreateReply(Ping(flags: flags), fixture.Peer, out byte[] duplicate);
                Check(reply.SequenceEqual(duplicate), "PING retransmission changed reply");
            }
            foreach (byte flags in new byte[] { 0, 8, 0x10, 0x30, 0x40, 0x48, 0x70, 0x80 })
                Check(!PrudpPingAckCodec.TryCreateReply(Ping(flags: flags), fixture.Peer, out _), "Unsupported PING flags replied");
            foreach (int index in new[] { 0, 1, 3, 4 })
            {
                byte[] wrong = Ping(); wrong[index] ^= 1; Sum(wrong);
                Check(!PrudpPingAckCodec.TryCreateReply(wrong, fixture.Peer, out _), "Wrong PING peer tuple replied");
            }
            byte[] badSum = Ping(); badSum[^1] ^= 1;
            byte[] payload = [.. Ping().AsSpan(0, 10), 99, 0, 0, 0, 0]; Sum(payload);
            Check(!PrudpPingAckCodec.TryCreateReply(badSum, fixture.Peer, out _)
                && !PrudpPingAckCodec.TryCreateReply(payload, fixture.Peer, out _)
                && !PrudpPingAckCodec.TryCreateReply([.. Ping(flags: 0x60), 0], fixture.Peer, out _), "Malformed PING replied");
            fixture.Register();
            Check(!fixture.Session.TryReplyToPing(Ping(), 200, fixture.Events.Add, out _), "Baseline probe enabled keepalive");
        }
        using (Fixture fixture = new(keepAlive: true))
        {
            var session = fixture.Session; Action<ConfigServerEvent> emit = fixture.Events.Add;
            Check(!session.TryReplyToPing(Ping(), 100, emit, out _), "Pre-login PING replied");
            fixture.Register();
            Check(session.TryReplyToPing(Ping(), 200, emit, out _), "Registered PING did not reply");
            Check(!session.TryReplyToPing(Ping(), 299, emit, out _), "PING rate limit failed");
            Check(session.TryReplyToPing(Ping(), 300, emit, out _), "PING rate window did not reopen");
            Check(session.TryReplyToPing(Ping(), 120099, emit, out _), "Valid PING before idle expiry failed");
            Check(session.TakeDue(120100, emit).Count == 0 && !session.Closed, "Active keepalive hit old absolute lifetime");
            Check(!session.TryReplyToPing(Ping(cookie: 3), 200000, emit, out _), "Invalid PING refreshed activity");
            Check(session.TakeDue(240099, emit).Count == 0 && session.Closed, "Idle deadline was extended by invalid traffic");
            Check(!session.TryReplyToPing(Ping(), 240100, emit, out _), "Expired session was revived");
        }
        using (Fixture fixture = new(keepAlive: true))
        {
            fixture.Register();
            for (long now = 60100; now < 1200100; now += 60000)
                Check(fixture.Session.TryReplyToPing(Ping(), now, fixture.Events.Add, out _), "Active session expired before hard cap");
            Check(!fixture.Session.TryReplyToPing(Ping(), 1200100, fixture.Events.Add, out _) && fixture.Session.Closed,
                "Keepalive bypassed absolute cap");
        }
        using (Fixture fixture = new())
        {
            var session = fixture.Session; Action<ConfigServerEvent> emit = fixture.Events.Add;
            byte[] login = Request(false); int first = login.Length / 3, second = first * 2;
            byte[] p1 = fixture.Data(6, 1, login.AsSpan(0, first));
            byte[] p2 = fixture.Data(7, 2, login.AsSpan(first, second - first));
            byte[] p3 = fixture.Data(8, 0, login.AsSpan(second));
            byte[] wrongCookie = (byte[])p1.Clone(); wrongCookie[4] ^= 1; Sum(wrongCookie);
            byte[] wrongSession = (byte[])p1.Clone(); wrongSession[3] ^= 1; Sum(wrongSession);
            Check(session.ProcessData(wrongCookie, emit).SequenceMatches != true && session.ProcessData(wrongSession, emit).SequenceMatches != true,
                "Wrong peer context reached assembly");
            session.ProcessData(p3, emit); session.ProcessData(p2, emit); session.ProcessData(p2, emit);
            Check(session.PendingCount == 0 && session.TakeDue(100, emit).Count == 0, "Sequence gap or duplicate produced RPC response");
            Check(session.ProcessData(p1, emit).SequenceMatches == true && session.PendingCount == 1, "Complete ordered Login did not queue response");
            Check(!session.TryAcknowledge(Ack(ServerCookie, 1)) && session.PendingCount == 1, "Guessed unsent ACK removed response");
            byte[] response = session.TakeDue(100, emit).Single(); byte[] snapshot = (byte[])response.Clone();
            byte[] decoded = DecodeResponse(response, fixture.Key, 0x456789ab, false, fixture.ServerSession); CryptographicOperations.ZeroMemory(decoded); passed++;
            Check(session.TakeDue(1099, emit).Count == 0, "Retry fired before deadline");
            byte[] retry = session.TakeDue(1100, emit).Single();
            Check(ReferenceEquals(response, retry) && retry.SequenceEqual(snapshot), "Retry regenerated ciphertext/IV or changed bytes");
            foreach (byte[] ack in new[] { Ack(ServerCookie ^ 1, 1), Ack(ServerCookie, 2), Ack(ServerCookie, 1) })
            {
                if (BinaryPrimitives.ReadUInt32LittleEndian(ack.AsSpan(4)) == ServerCookie && BinaryPrimitives.ReadUInt16LittleEndian(ack.AsSpan(8)) == 1) { ack[3] ^= 1; Sum(ack); }
                Check(!session.TryAcknowledge(ack) && session.PendingCount == 1, "Mismatched ACK removed pending response");
            }
            byte[] badPart = Ack(ServerCookie, 1); badPart[10] = 1; Sum(badPart);
            byte[] withPayload = [.. Ack(ServerCookie, 1).AsSpan(0, 11), 0, 0, 0, 0, 0]; Sum(withPayload);
            byte[] trailing = [.. Ack(ServerCookie, 1, true), 0];
            Check(!session.TryAcknowledge(badPart) && !session.TryAcknowledge(withPayload) && !session.TryAcknowledge(trailing), "Malformed ACK accepted");
            Check(session.TryAcknowledge(Ack(ServerCookie, 1, true)) && session.PendingCount == 0 && response.All(value => value == 0), "ACK failed to clear ciphertext storage");
            Check(!session.TryAcknowledge(Ack(ServerCookie, 1)), "Duplicate ACK accepted");
            session.ProcessData(p1, emit); session.ProcessData(p2, emit); session.ProcessData(p3, emit);
            Check(session.PendingCount == 0, "Consumed Login fragments replayed RPC");
            byte[] register = fixture.Data(9, 0, Request(true, 0x456789ac));
            session.ProcessData(register, emit); session.ProcessData(register, emit);
            Check(session.PendingCount == 1, "Register missing or duplicate queued extra response");
            byte[] registered = session.TakeDue(1200, emit).Single();
            Check(BinaryPrimitives.ReadUInt16LittleEndian(registered.AsSpan(8)) == 2, "Server sequence did not advance independently");
            decoded = DecodeResponse(registered, fixture.Key, 0x456789ac, true, fixture.ServerSession); CryptographicOperations.ZeroMemory(decoded); passed++;
            Check(session.TryAcknowledge(Ack(ServerCookie, 2)) && registered.All(value => value == 0), "Register ACK did not clear storage");
            Check(fixture.Events.Count(item => item.Event == "local-login-response-queued") == 2, "RPC response budget or duplicate suppression failed");
            string json = JsonSerializer.Serialize(fixture.Events);
            Check(!json.Contains("test-secret") && !json.Contains(PublicUrl) && !json.Contains(Convert.ToHexString(fixture.Key)), "Session events exposed argument/key material");
        }
        using (Fixture fixture = new())
        {
            int callbacks = 0; byte[] good = fixture.Data(6, 0, [1, 2, 3]);
            Check(PrudpDataCryptoProbe.Inspect(good, fixture.Peer, bytes => { if (!bytes.SequenceEqual(new byte[] { 1, 2, 3 })) throw new Exception("Callback plaintext differs"); callbacks++; }).SequenceMatches == true && callbacks == 1, "Verified callback missing");
            byte[] wrongSequence = (byte[])good.Clone(); wrongSequence[8] ^= 1; Sum(wrongSequence);
            byte[] badPadding = fixture.Data(6, 0, []); badPadding[26] ^= 13; Sum(badPadding);
            byte[] invalidContext = (byte[])good.Clone(); invalidContext[3] ^= 1; Sum(invalidContext);
            byte[] badZlib = (byte[])good.Clone(); badZlib[11] ^= 1; Sum(badZlib);
            byte[] emptyBody = Ack(ServerCookie, 6); emptyBody[2] = 0x32; Sum(emptyBody);
            foreach (byte[] invalid in new[] { wrongSequence, badPadding, badZlib, emptyBody, invalidContext, Ack(ServerCookie, 6) })
                Check(PrudpDataCryptoProbe.Inspect(invalid, fixture.Peer, _ => callbacks++).SequenceMatches != true && callbacks == 1, "Failed crypto/context invoked plaintext callback");
            Check(PrudpDataCryptoProbe.InspectBody(new byte[31], 6, fixture.Key, _ => callbacks++).SequenceMatches != true && callbacks == 1, "Invalid CBC length invoked callback");
        }
        foreach (bool lifetime in new[] { false, true })
        {
            using Fixture fixture = new(); fixture.Login();
            byte[] storage = fixture.Session.TakeDue(100, fixture.Events.Add).Single();
            byte[] ownedKey = (byte[])typeof(PrudpLocalLoginSession).GetField("key", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(fixture.Session)!;
            if (lifetime) Check(fixture.Session.TakeDue(100 + PrudpLocalLoginSession.LifetimeMilliseconds, fixture.Events.Add).Count == 0, "Lifetime sent expired response");
            else
            {
                for (int index = 1; index < PrudpLocalLoginSession.MaximumTransmissions; index++)
                    Check(ReferenceEquals(storage, fixture.Session.TakeDue(100 + index * PrudpLocalLoginSession.RetryMilliseconds, fixture.Events.Add).Single()), "Retry storage changed");
                Check(fixture.Session.TakeDue(100 + PrudpLocalLoginSession.MaximumTransmissions * PrudpLocalLoginSession.RetryMilliseconds, fixture.Events.Add).Count == 0, "Retry limit exceeded");
            }
            Check(fixture.Session.Closed && fixture.Session.PendingCount == 0 && storage.All(value => value == 0) && ownedKey.All(value => value == 0), "Expiry did not clear owned key/ciphertext");
            Check(fixture.Session.ProcessData(fixture.Data(7, 0, Request(true)), fixture.Events.Add).Outcome == "local-login-session-closed"
                && !fixture.Session.TryAcknowledge(Ack(ServerCookie, 1)), "Closed session remained usable");
        }
        using (Fixture fixture = new())
        {
            fixture.Login(); byte[] storage = fixture.Session.TakeDue(100, fixture.Events.Add).Single();
            fixture.Session.Dispose(); fixture.Session.Dispose();
            Check(storage.All(value => value == 0) && fixture.Session.Closed, "Explicit disposal retained ciphertext");
        }
        return passed;
    }

    internal static async Task<int> RunNetworkAsync()
    {
        if (!OperatingSystem.IsWindows()) return 0;
        int passed = 0;
        void Check(bool value, string label) { if (!value) throw new Exception(label); passed++; }
        ConcurrentQueue<ConfigServerEvent> events = new();
        TaskCompletionSource<ConfigServerEvent> ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource stop = new();
        Task service = LocalConfigurationServer.RunAsync(new() { HttpPort = 0, UdpPort = 0, LocalKeepAliveProbe = true, Seconds = 30 },
            item => { events.Enqueue(item); if (item.Event == "configuration-server-ready") ready.TrySetResult(item); }, stop.Token);
        ConfigServerEvent info = await ready.Task.WaitAsync(TimeSpan.FromSeconds(5));
        using UdpClient client = new(AddressFamily.InterNetwork); client.Connect(IPAddress.Loopback, info.UdpPort!.Value);
        using ECDiffieHellman agreement = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        byte[] key = null;
        async Task<byte[]> Receive(int timeout = 3000)
        { using CancellationTokenSource deadline = new(timeout); return (await client.ReceiveAsync(deadline.Token)).Buffer; }
        async Task Silence(int milliseconds)
        {
            using CancellationTokenSource deadline = new(milliseconds);
            try { await client.ReceiveAsync(deadline.Token); throw new Exception("Unexpected extra response"); }
            catch (OperationCanceledException) { passed++; }
        }
        async Task Wait(Func<bool> condition)
        {
            using CancellationTokenSource deadline = new(3000);
            while (!condition()) await Task.Delay(10, deadline.Token);
        }
        try
        {
            byte[] syn = new byte[18]; syn[0] = 0x3a; syn[1] = 0x31; syn[2] = 0x20; Sum(syn);
            await client.SendAsync(syn); byte[] synAck = await Receive();
            Check(synAck.Length == 18, "SYN ACK missing"); uint cookie = BinaryPrimitives.ReadUInt32LittleEndian(synAck.AsSpan(10));
            await client.SendAsync(Connect(cookie, agreement)); byte[] connectAck = await Receive();
            Check(connectAck.Length == 158, "CONNECT ACK missing"); key = NativeCngFixtures.Derive(agreement, connectAck.AsSpan(82, 72).ToArray());
            byte serverSession = connectAck[3]; int publicPort = ((IPEndPoint)client.Client.LocalEndPoint!).Port;
            byte[] login = Request(false); int split = login.Length / 2;
            byte[] first = Data(cookie, key, 6, 1, login.AsSpan(0, split)), last = Data(cookie, key, 7, 0, login.AsSpan(split));
            await client.SendAsync(last); Check((await Receive()).Length == 15, "Out-of-order fragment was not ACKed"); await Silence(150);
            await client.SendAsync(first); byte[] firstReceived = await Receive(), secondReceived = await Receive();
            byte[] response = firstReceived.Length == 15 ? secondReceived : firstReceived;
            Check(firstReceived.Length == 15 || secondReceived.Length == 15, "Login fragment transport ACK missing");
            byte[] decoded = DecodeResponse(response, key, 0x456789ab, false, serverSession, info.UdpPort.Value, publicPort); CryptographicOperations.ZeroMemory(decoded); passed++;
            byte[] retry = await Receive(); Check(retry.SequenceEqual(response), "Actual UDP retry changed ciphertext bytes");
            await client.SendAsync(Ack(cookie, BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(8))));
            await Wait(() => events.Any(item => item.Event == "local-login-ack-observed" && item.Reason == "response-acknowledged"));
            await Silence(1200);
            await client.SendAsync(first); Check((await Receive()).Length == 15, "Duplicate DATA transport ACK missing"); await Silence(150);
            await client.SendAsync(Data(cookie, key, 8, 0, Request(true, 0x456789ac)));
            firstReceived = await Receive(); secondReceived = await Receive();
            response = firstReceived.Length == 15 ? secondReceived : firstReceived;
            Check(firstReceived.Length == 15 || secondReceived.Length == 15, "Register transport ACK missing");
            decoded = DecodeResponse(response, key, 0x456789ac, true, serverSession, info.UdpPort.Value, publicPort); CryptographicOperations.ZeroMemory(decoded); passed++;
            await client.SendAsync(Ack(cookie, BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(8))));
            await Wait(() => events.Count(item => item.Event == "local-login-ack-observed" && item.Reason == "response-acknowledged") == 2);
            byte[] ping = new byte[14]; ping[0] = 0x3a; ping[1] = 0x31; ping[2] = 4; ping[3] = ClientSession;
            BinaryPrimitives.WriteUInt32LittleEndian(ping.AsSpan(4), cookie); Sum(ping); await client.SendAsync(ping);
            await Wait(() => events.Any(item => item.Event == "udp-datagram-observed" && item.PacketType == "ping"));
            await Silence(1200);
            await client.SendAsync(Ping(cookie));
            byte[] pingAck = await Receive();
            Check(PrudpControlPacketDecoder.TryDecode(pingAck, out var control, out _, 0)
                && control.Type == PrudpControlPacketType.Ping && control.Flags == 8 && control.SequenceId == 12
                && control.PayloadLength == 0 && control.SessionId == serverSession && control.PacketSignature == ClientCookie,
                "Actual UDP PING ACK differs");
            await Wait(() => events.Any(item => item.Event == "local-ping-ack-sent"));
            await client.SendAsync(Ping(cookie, 8)); await Silence(150);
            await client.SendAsync(Ping(cookie ^ 1)); await Silence(150);
            Check(events.Count(item => item.Event == "local-login-response-queued") == 2, "Network RPC duplication or missing registration");
            string json = string.Join("\n", events.Select(item => JsonSerializer.Serialize(item, ConfigServerJsonContext.Default.ConfigServerEvent)));
            Check(!json.Contains("test-secret") && !json.Contains(PublicUrl) && !json.Contains(Convert.ToHexString(key))
                && !json.Contains("\"call_id\"") && !json.Contains("\"profile_id\""), "Network logs exposed private protocol values");
        }
        finally
        {
            if (key != null) CryptographicOperations.ZeroMemory(key);
            stop.Cancel(); await service.WaitAsync(TimeSpan.FromSeconds(5));
        }
        Check(events.Last().Event == "configuration-server-stopped", "Stop event preceded service cleanup");
        using (TcpListener rebound = new(IPAddress.Loopback, info.HttpPort!.Value))
        { rebound.Server.ExclusiveAddressUse = true; rebound.Start(); passed++; }
        using (UdpClient rebound = new(AddressFamily.InterNetwork))
        { rebound.Client.ExclusiveAddressUse = true; rebound.Client.Bind(new IPEndPoint(IPAddress.Loopback, info.UdpPort!.Value)); passed++; }
        return passed;
    }
}
