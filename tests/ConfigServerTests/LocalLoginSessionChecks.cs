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
    private static void VerifySearchResponse(byte[] packet, byte[] key, uint callId, byte serverSession, byte[] expected = null)
    {
        expected ??= LocalSessionSearchChecks.EmptyResponse(callId);
        if (!PrudpDataPacketDecoder.TryDecode(packet, out var data, out _, 0) || data.BytesConsumed != packet.Length
            || packet[0] != 0x31 || packet[1] != 0x3a || packet[2] != 0x32 || packet[3] != serverSession || packet[10] != 0
            || BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(4)) != ClientCookie)
            throw new Exception("Invalid search response transport");
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
            if (expanded.Length != expected.Length + 2 || BinaryPrimitives.ReadUInt16LittleEndian(expanded.AsSpan(expected.Length))
                != BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(8))
                || !expanded.AsSpan(0, expected.Length).SequenceEqual(expected))
                throw new Exception("Search response differs from fixed native wire vector");
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
        internal Fixture(long now = 100, bool keepAlive = false, LocalSessionRegistry sessions = null, LocalNetworkPolicy network = null)
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
            Session = new(Peer, new(network?.PeerAddress ?? IPAddress.Loopback, 40000),
                "prudp:/address=" + (network?.BindAddress ?? IPAddress.Loopback) + ";port=9111;sid=1;stream=3;type=2",
                now, keepAlive, sessions, network);
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

    private static int RunLanLifetimeChecks()
    {
        int passed = 0;
        void Check(bool ok, string why) { if(!ok) throw new Exception(why); passed++; }
        foreach(bool reversed in new[]{false,true})
        {
            string left = reversed ? "192.168.10.20" : "192.168.10.10";
            string right = reversed ? "192.168.10.10" : "192.168.10.20";
            Check(LocalNetworkPolicy.TryCreate(left,right,out var policy), "LAN lifetime policy fixture");
            using var fixture = new Fixture(keepAlive:true,network:policy);
            fixture.Register();
            Check(fixture.Events.Count(e=>e.Event=="local-login-response-queued")==2 && fixture.Session.PendingCount==0,
                "LAN lifetime registration fixture");
            ushort requestSequence=8, replySequence=3;
            for(int i=0;i<PrudpLocalLoginSession.LanResponsesPerWindow;i++)
            {
                long now=1000+i;
                fixture.Session.ProcessData(fixture.Data(requestSequence++,0,LocalSessionSearchChecks.Request()),fixture.Events.Add,now);
                byte[] response=fixture.Session.TakeDue(now,fixture.Events.Add).Single();
                VerifySearchResponse(response,fixture.Key,0x12345678,fixture.ServerSession); passed++;
                Check(fixture.Session.TryAcknowledge(Ack(ServerCookie,replySequence++)), "LAN window reply ACK");
            }
            fixture.Session.ProcessData(fixture.Data(requestSequence++,0,LocalSessionSearchChecks.Request()),fixture.Events.Add,2000);
            Check(fixture.Session.TakeDue(2000,fixture.Events.Add).Count==0
                && fixture.Events.Any(e=>e.Reason=="response-budget-exhausted"), "LAN reply rate limit missing");
            long reopened=100+PrudpLocalLoginSession.LanResponseWindowMilliseconds;
            fixture.Session.ProcessData(fixture.Data(requestSequence++,0,LocalSessionSearchChecks.Request()),fixture.Events.Add,reopened);
            Check(fixture.Session.TakeDue(reopened,fixture.Events.Add).Count==1
                && fixture.Session.TryAcknowledge(Ack(ServerCookie,replySequence++)), "LAN reply window never reopened");
            long beyondOldCap=100+2*60*60*1000;
            for(long now=reopened+60000;now<beyondOldCap;now+=60000)
                Check(fixture.Session.TryReplyToPing(Ping(),now,fixture.Events.Add,out _), "Active LAN expired at probe cap");
            fixture.Session.ProcessData(fixture.Data(requestSequence++,0,LocalSessionSearchChecks.Request()),fixture.Events.Add,beyondOldCap);
            Check(fixture.Session.TakeDue(beyondOldCap,fixture.Events.Add).Count==1
                && fixture.Session.TryAcknowledge(Ack(ServerCookie,replySequence++)), "LAN RPC failed after old lifetime");
            long hardEnd=100+PrudpLocalLoginSession.LanMaximumMilliseconds;
            for(long now=beyondOldCap+600000;now<hardEnd;now+=600000)
                Check(fixture.Session.TryReplyToPing(Ping(),now,fixture.Events.Add,out _), "LAN expired before declared maximum");
            Check(!fixture.Session.TryReplyToPing(Ping(),hardEnd,fixture.Events.Add,out _) && fixture.Session.Closed,
                "LAN absolute lifetime removed");
            Check(fixture.Events.Last(e=>e.Event=="local-login-session-expired").Reason=="keepalive-maximum-ended",
                "Wrong LAN maximum expiry reason");
            using var idle = new Fixture(keepAlive:true,network:policy);
            idle.Register(); idle.Session.TakeDue(100+PrudpLocalLoginSession.LanIdleMilliseconds,idle.Events.Add);
            Check(idle.Session.Closed, "Idle LAN registration never expired");
            using var baseline = new Fixture(network:policy);
            baseline.Register(); baseline.Session.TakeDue(100+PrudpLocalLoginSession.LifetimeMilliseconds,baseline.Events.Add);
            Check(baseline.Session.Closed, "LAN addresses expanded baseline non-keepalive probe");
        }
        return passed;
    }

    internal static int Run()
    {
        if (!OperatingSystem.IsWindows()) { Console.WriteLine("SKIP: native BCrypt local-login session checks require Windows."); return 0; }
        int passed = RunLanLifetimeChecks();
        void Check(bool value, string label) { if (!value) throw new Exception(label); passed++; }
        // A busy browser may send RPCs instead of PINGs. Advancing receive
        // timestamps must extend only successfully handled registered activity.
        long idle = PrudpLocalLoginSession.KeepAliveIdleMilliseconds;
        using (Fixture fixture = new(keepAlive:true))
        {
            fixture.Register();
            long acceptedAt = 100 + idle / 2;
            fixture.Session.ProcessData(fixture.Data(8, 0, LocalSessionSearchChecks.Request()), fixture.Events.Add, acceptedAt);
            Check(fixture.Session.TakeDue(acceptedAt, fixture.Events.Add).Count==1
                && fixture.Session.TryAcknowledge(Ack(ServerCookie,3)), "Timed search not answered");
            fixture.Session.TakeDue(100 + idle, fixture.Events.Add);
            Check(!fixture.Session.Closed, "Active registered RPC expired at old idle deadline");
            fixture.Session.TakeDue(acceptedAt + idle, fixture.Events.Add);
            Check(fixture.Session.Closed, "Activity removed idle expiry");
            Check(fixture.Session.ProcessData(fixture.Data(9,0,LocalSessionSearchChecks.Request()), fixture.Events.Add,
                acceptedAt + idle + 1).Outcome=="local-login-session-closed", "Timed DATA revived closed session");
        }
        foreach (bool duplicate in new[]{false,true})
        using (Fixture fixture = new(keepAlive:true))
        {
            fixture.Register();
            byte[] packet = fixture.Data(8,0,LocalSessionSearchChecks.Request());
            fixture.Session.ProcessData(packet, fixture.Events.Add, 200);
            fixture.Session.TakeDue(200, fixture.Events.Add); fixture.Session.TryAcknowledge(Ack(ServerCookie,3));
            byte[] rejected = duplicate ? packet : fixture.Data(9,0,LocalSessionSearchChecks.Request(body:[0]));
            fixture.Session.ProcessData(rejected, fixture.Events.Add, 100 + idle);
            fixture.Session.TakeDue(200 + idle, fixture.Events.Add);
            Check(fixture.Session.Closed, "Rejected/duplicate RPC refreshed idle activity");
        }
        using (Fixture fixture = new(keepAlive:true))
        {
            fixture.Register();
            fixture.Session.ProcessData(fixture.Data(8,0,LocalSessionSearchChecks.Request()), fixture.Events.Add, 100 + idle);
            Check(fixture.Session.Closed && fixture.Session.PendingCount==0, "DATA at deadline revived expired registration");
        }
        using (Fixture fixture = new(keepAlive:true))
        {
            fixture.Register();
            long hardEnd = 100 + PrudpLocalLoginSession.KeepAliveMaximumMilliseconds;
            long acceptedAt = hardEnd - idle / 2;
            for(long now=60100;now<acceptedAt;now+=60000)
                fixture.Session.TryReplyToPing(Ping(),now,fixture.Events.Add,out _);
            fixture.Session.ProcessData(fixture.Data(8,0,LocalSessionSearchChecks.Request()), fixture.Events.Add, acceptedAt);
            fixture.Session.TakeDue(acceptedAt,fixture.Events.Add); fixture.Session.TryAcknowledge(Ack(ServerCookie,3));
            fixture.Session.TakeDue(hardEnd,fixture.Events.Add);
            Check(fixture.Session.Closed && fixture.Events.Last(e=>e.Event=="local-login-session-expired").Reason=="keepalive-maximum-ended",
                "Active RPC bypassed absolute lifetime");
        }
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
            long idleEnd = 120099 + PrudpLocalLoginSession.KeepAliveIdleMilliseconds;
            Check(session.TakeDue(idleEnd, emit).Count == 0 && session.Closed, "Idle deadline was extended by invalid traffic");
            Check(!session.TryReplyToPing(Ping(), idleEnd + 1, emit, out _), "Expired session was revived");
        }
        using (Fixture fixture = new(keepAlive: true))
        {
            fixture.Register();
            long hardEnd = 100 + PrudpLocalLoginSession.KeepAliveMaximumMilliseconds;
            for (long now = 60100; now < hardEnd; now += 60000)
                Check(fixture.Session.TryReplyToPing(Ping(), now, fixture.Events.Add, out _), "Active session expired before hard cap");
            Check(!fixture.Session.TryReplyToPing(Ping(), hardEnd, fixture.Events.Add, out _) && fixture.Session.Closed,
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
        using (Fixture fixture = new(keepAlive: true))
        {
            fixture.Register();
            Check(!fixture.Events.Any(e => e.Event == "local-post-login-request-observed"), "Classifier ran before response budget");
            byte[] search = [0, 0, 0, 0, .. Ddl("MatchmakingProtocol"), 1, 7, 0, 0, 0,
                .. Ddl("MatchmakingProtocol::SearchSessions_V1"), .. Ddl("invented-private-body")];
            BinaryPrimitives.WriteUInt32LittleEndian(search, (uint)(search.Length - 4));
            for (ushort sequence = 8; sequence < 18; sequence++)
            {
                byte[] packet = fixture.Data(sequence, 0, search);
                fixture.Session.ProcessData(packet, fixture.Events.Add);
                fixture.Session.ProcessData(packet, fixture.Events.Add); // Retransmission is not a new observation.
            }
            var observations = fixture.Events.Where(e => e.Event == "local-post-login-request-observed").ToArray();
            Check(observations.Length == 1 && observations[0].Reason == "matchmaking-search-sessions-v1", "Repeated operation consumed diagnostic budget");
            string[] methods = ["GetSession", "CreateSession", "UpdateSession", "JoinSession", "LeaveSession", "LockSession", "UnlockSession", "CreateSession2", "ReportHostSuccess"];
            for (int i = 0; i < methods.Length; ++i)
                fixture.Session.ProcessData(fixture.Data((ushort)(18 + i), 0,
                    LocalSessionCreationChecks.Request(body: [], method: "MatchmakingProtocol::" + methods[i] + "_V1")), fixture.Events.Add);
            Check(fixture.Events.Count(e => e.Event == "local-post-login-request-observed") == 8
                && !fixture.Events.Any(e => e.Reason == "matchmaking-create-session2-v1"), "Distinct operation diagnostic cap exceeded");
            Check(fixture.Session.PendingCount == 0 && fixture.Session.TakeDue(200, fixture.Events.Add).Count == 0,
                "Observation enlarged response budget");
            Check(fixture.Session.TryReplyToPing(Ping(), 200, fixture.Events.Add, out _), "Observation disrupted keepalive");
            Check(fixture.Events.All(e => !JsonSerializer.Serialize(e, ConfigServerJsonContext.Default.ConfigServerEvent).Contains("invented-private-body")),
                "Diagnostic event leaked argument bytes");
        }
        using (Fixture fixture = new())
        {
            fixture.Register();
            fixture.Session.ProcessData(fixture.Data(8, 0, LocalSessionSearchChecks.Request()), fixture.Events.Add);
            Check(fixture.Session.PendingCount == 0, "Baseline login probe unexpectedly enabled search replies");
        }
        using (Fixture fixture = new(keepAlive: true))
        {
            fixture.Login(); fixture.Session.TakeDue(100, fixture.Events.Add);
            fixture.Session.TryAcknowledge(Ack(ServerCookie, 1));
            fixture.Session.ProcessData(fixture.Data(7, 0, Request(true)), fixture.Events.Add);
            fixture.Session.ProcessData(fixture.Data(8, 0, LocalSessionSearchChecks.Request()), fixture.Events.Add);
            Check(fixture.Session.PendingCount == 1 && !fixture.Events.Any(e => e.Event == "local-session-search-response-queued"),
                "Search replied before Register acknowledgement");
        }
        using (Fixture fixture = new(keepAlive: true))
        {
            fixture.Register();
            for (ushort i = 0; i < PrudpLocalLoginSession.MaximumPostLoginResponses; ++i)
            {
                byte[] packet = fixture.Data((ushort)(8 + i), 0, LocalSessionSearchChecks.Request(i));
                long now = 2000 + i * 1000;
                fixture.Session.ProcessData(packet, fixture.Events.Add, now);
                fixture.Session.ProcessData(packet, fixture.Events.Add, now);
                Check(fixture.Session.PendingCount == 1, "Duplicate search requeued a response");
                byte[] response = fixture.Session.TakeDue(now, fixture.Events.Add).Single();
                VerifySearchResponse(response, fixture.Key, i, fixture.ServerSession); passed++;
                if (i == 0)
                {
                    Check(fixture.Session.TakeDue(2999, fixture.Events.Add).Count == 0, "Search retried early");
                    Check(ReferenceEquals(response, fixture.Session.TakeDue(3000, fixture.Events.Add).Single()), "Search retry changed ciphertext");
                }
                Check(fixture.Session.TryAcknowledge(Ack(ServerCookie, (ushort)(3 + i))) && response.All(b => b == 0),
                    "Search ACK failed to clear response ciphertext");
            }
            fixture.Session.ProcessData(fixture.Data((ushort)(8 + PrudpLocalLoginSession.MaximumPostLoginResponses), 0, LocalSessionSearchChecks.Request()), fixture.Events.Add);
            Check(fixture.Session.PendingCount == 0 && fixture.Events.Count(e => e.Event == "local-session-search-response-queued") == PrudpLocalLoginSession.MaximumPostLoginResponses,
                "Search response cap exceeded");
            Check(fixture.Session.TryReplyToPing(Ping(), 2000 + PrudpLocalLoginSession.MaximumPostLoginResponses * 1000, fixture.Events.Add, out _), "Search budget broke keepalive");
        }
        using (Fixture fixture = new(keepAlive: true))
        {
            fixture.Register();
            for (ushort i = 8; i < 11; ++i)
                fixture.Session.ProcessData(fixture.Data(i, 0, LocalSessionSearchChecks.Request(i)), fixture.Events.Add);
            Check(fixture.Session.PendingCount == 2 && fixture.Events.Count(e => e.Event == "local-session-search-response-queued") == 2,
                "Search pending window exceeded");
        }
        // Inject an invented large response into the managed test fixture's
        // queue to exercise the real session ACK/context layer. No new RPC or
        // production debug endpoint is exposed by this transport test.
        using (Fixture fixture = new(keepAlive: true))
        {
            fixture.Register();
            var queue = (ReliableResponseQueue)typeof(PrudpLocalLoginSession)
                .GetField("pending", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(fixture.Session)!;
            Check(queue.TryEnqueue(new byte[1900],
                (seq, part, bytes) => fixture.Peer.Connect.CreateDataPacket(seq, bytes, fixture.Key, part)),
                "Large response fixture failed");
            byte[] FragmentAck(ushort seq, byte part, bool explicitLength = false)
            { byte[] ack = Ack(ServerCookie, seq, explicitLength); ack[10] = part; Sum(ack); return ack; }
            Check(!fixture.Session.TryAcknowledge(FragmentAck(3, 1)), "Session accepted unsent fragment ACK");
            var first = fixture.Session.TakeDue(200, fixture.Events.Add);
            Check(first.Count == 2 && first[0][10] == 1 && first[1][10] == 2
                && first.All(p => p[3] == fixture.ServerSession
                    && BinaryPrimitives.ReadUInt32LittleEndian(p.AsSpan(4)) == ClientCookie),
                "Session discarded fragment parts or CONNECT context");
            foreach (int field in new[] { 0, 1, 3, 4 })
            {
                byte[] wrong = FragmentAck(3, 1); wrong[field] ^= 1; Sum(wrong);
                Check(!fixture.Session.TryAcknowledge(wrong), "Fragment ACK bypassed peer/session/cookie guard");
            }
            byte[] corrupt = FragmentAck(3, 1); corrupt[^1] ^= 1;
            Check(!fixture.Session.TryAcknowledge(corrupt) && !fixture.Session.TryAcknowledge(FragmentAck(3, 0)),
                "Fragment ACK bypassed checksum/part guard");
            Check(fixture.Session.TryAcknowledge(FragmentAck(4, 2, true)) && first[1].All(b => b == 0)
                && fixture.Session.PendingCount == 1, "Later fragment ACK completed entire response");
            Check(fixture.Session.TakeDue(201, fixture.Events.Add).Count == 0
                && !fixture.Session.TryAcknowledge(FragmentAck(5, 0)), "Session advanced past missing fragment ACK");
            Check(fixture.Session.TryAcknowledge(FragmentAck(3, 1)), "Matching nonzero part ACK rejected");
            byte[] final = fixture.Session.TakeDue(201, fixture.Events.Add).Single();
            Check(final[10] == 0 && BinaryPrimitives.ReadUInt16LittleEndian(final.AsSpan(8)) == 5,
                "Final fragment did not use next sequence and part zero");
            Check(fixture.Session.TryAcknowledge(FragmentAck(5, 0)) && final.All(b => b == 0)
                && fixture.Session.PendingCount == 0 && fixture.Session.TryReplyToPing(Ping(), 202, fixture.Events.Add, out _),
                "Completed multipart response retained storage or broke keepalive");
        }
        using (LocalSessionRegistry registry = new())
        using (Fixture host = new(keepAlive: true, sessions: registry))
        using (Fixture visitor = new(keepAlive: true, sessions: registry))
        {
            host.Register(); visitor.Register();
            byte[] create = host.Data(8, 0, LocalSessionCreationChecks.Request());
            host.Session.ProcessData(create, host.Events.Add);
            host.Session.ProcessData(create, host.Events.Add);
            Check(registry.Count == 1 && host.Session.PendingCount == 1, "Create transport retry duplicated record");
            Check(registry.TryGetHost(host.Session, 1, out var registeredHost), "Encrypted create lost registered host");
            using (registeredHost)
                Check(registeredHost.ProfileId.Length == 16 && registeredHost.ProfileId.IndexOfAnyExcept((byte)0) >= 0
                    && registeredHost.ConnectionId != 0 && registeredHost.PublicUrl.Contains("address=127.0.0.1;port=40000")
                    && !registry.TryGetHost(visitor.Session, 1, out _), "Encrypted create host routing or ownership differs");
            byte[] reply = host.Session.TakeDue(200, host.Events.Add).Single();
            VerifySearchResponse(reply, host.Key, 0x12345678, host.ServerSession, LocalSessionCreationChecks.Response()); passed++;
            Check(ReferenceEquals(reply, host.Session.TakeDue(1200, host.Events.Add).Single()), "Create retry ciphertext changed");
            Check(host.Session.TryAcknowledge(Ack(ServerCookie, 3)) && reply.All(b => b == 0), "Create reply ACK not cleared");
            host.Session.ProcessData(host.Data(9, 0, LocalSessionCreationChecks.Request(7)), host.Events.Add);
            reply = host.Session.TakeDue(1300, host.Events.Add).Single();
            VerifySearchResponse(reply, host.Key, 7, host.ServerSession, LocalSessionCreationChecks.Response(7)); passed++;
            Check(registry.Count == 1 && host.Session.TryAcknowledge(Ack(ServerCookie, 4)), "Application create retry duplicated record");
            host.Session.ProcessData(host.Data(10, 0, LocalSessionCreationChecks.Request(method: "MatchmakingProtocol::GetSession_V1")), host.Events.Add);
            Check(host.Session.PendingCount == 0 && registry.Count == 1
                && host.Events.Any(e => e.Event == "local-post-login-request-observed" && e.Reason == "matchmaking-get-session-v1")
                && host.Events.Any(e => e.Reason == "unsupported-session-operation")
                && !host.Events.Any(e => e.Reason == "nonempty-session-catalogue-not-yet-supported"),
                "Unsupported follow-up changed registry or was misreported as a search");
            byte[] update = host.Data(11, 0, LocalSessionUpdateChecks.Request());
            host.Session.ProcessData(update, host.Events.Add); host.Session.ProcessData(update, host.Events.Add);
            Check(host.Session.PendingCount == 1 && host.Events.Count(e => e.Event == "local-session-update-response-queued") == 1,
                "Update transport retry queued another reply");
            reply = host.Session.TakeDue(1350, host.Events.Add).Single();
            VerifySearchResponse(reply, host.Key, 0x12345678, host.ServerSession, LocalSessionUpdateChecks.Response()); passed++;
            Check(ReferenceEquals(reply, host.Session.TakeDue(2350, host.Events.Add).Single()), "Update retry changed ciphertext");
            Check(host.Session.TryAcknowledge(Ack(ServerCookie, 5)) && reply.All(b => b == 0), "Update ACK failed to clear ciphertext");
            Check(registry.TryGetMetadata(host.Session, 1, out var updated), "Transport update lost record");
            using (updated) Check(updated.Attributes[Convert.ToHexString("attribute"u8)].SequenceEqual(new byte[] { 3, 1 }), "Transport update not persisted");
            visitor.Session.ProcessData(visitor.Data(8, 0, LocalSessionSearchChecks.Request()), visitor.Events.Add);
            Check(visitor.Session.PendingCount == 0 && visitor.Events.Any(e => e.Reason == "nonempty-session-catalogue-not-yet-supported"),
                "Other peer received false empty catalogue");
            visitor.Session.ProcessData(visitor.Data(9, 0, LocalSessionCreationChecks.Request()), visitor.Events.Add);
            reply = visitor.Session.TakeDue(1400, visitor.Events.Add).Single();
            VerifySearchResponse(reply, visitor.Key, 0x12345678, visitor.ServerSession, LocalSessionCreationChecks.Response(sessionId: 2)); passed++;
            Check(visitor.Session.TryAcknowledge(Ack(ServerCookie, 3)) && registry.Count == 2, "Second owner did not obtain separate record");
            host.Session.Dispose(); Check(registry.Count == 1, "Host teardown affected another owner");
            visitor.Session.TakeDue(100 + PrudpLocalLoginSession.KeepAliveIdleMilliseconds, visitor.Events.Add);
            Check(visitor.Session.Closed && registry.Count == 0, "Owner expiry leaked session record");
            Check(host.Events.Concat(visitor.Events).All(e => !JsonSerializer.Serialize(e, ConfigServerJsonContext.Default.ConfigServerEvent).Contains("invented-")),
                "Create events leaked body fields");
        }
        using (LocalSessionRegistry registry = new())
        using (Fixture fixture = new(keepAlive: true, sessions: registry))
        {
            fixture.Register();
            fixture.Session.ProcessData(fixture.Data(8, 0, LocalSessionCreationChecks.Request()), fixture.Events.Add);
            fixture.Session.TakeDue(100, fixture.Events.Add); fixture.Session.TryAcknowledge(Ack(ServerCookie, 3));
            for (ushort i = 0; i < PrudpLocalLoginSession.MaximumPostLoginResponses - 1; ++i)
            {
                fixture.Session.ProcessData(fixture.Data((ushort)(9 + i), 0, LocalSessionUpdateChecks.Request(i)), fixture.Events.Add);
                byte[] response = fixture.Session.TakeDue(200 + i * 10, fixture.Events.Add).Single();
                VerifySearchResponse(response, fixture.Key, i, fixture.ServerSession, LocalSessionUpdateChecks.Response(i)); passed++;
                Check(fixture.Session.TryAcknowledge(Ack(ServerCookie, (ushort)(4 + i))), "Update budget response ACK failed");
            }
            fixture.Session.ProcessData(fixture.Data((ushort)(8 + PrudpLocalLoginSession.MaximumPostLoginResponses), 0, LocalSessionUpdateChecks.Request(body: LocalSessionUpdateChecks.Body(attributes: LocalSessionUpdateChecks.Map()))), fixture.Events.Add);
            Check(fixture.Session.PendingCount == 0 && fixture.Events.Count(e => e.Event == "local-session-update-response-queued") == PrudpLocalLoginSession.MaximumPostLoginResponses - 1
                && fixture.Events.Any(e => e.Reason == "response-budget-exhausted"), "Updates bypassed shared response cap");
            fixture.Session.ProcessData(fixture.Data((ushort)(9 + PrudpLocalLoginSession.MaximumPostLoginResponses), 0, LocalSessionLeaveChecks.Request()), fixture.Events.Add);
            Check(registry.Count == 1 && fixture.Session.PendingCount == 0, "Leave mutated registry after response budget exhaustion");
        }
        using (LocalSessionRegistry registry = new())
        using (Fixture host = new(keepAlive: true, sessions: registry))
        using (Fixture visitor = new(keepAlive: true, sessions: registry))
        {
            host.Register(); visitor.Register();
            host.Session.ProcessData(host.Data(8, 0, LocalSessionCreationChecks.Request()), host.Events.Add);
            host.Session.TakeDue(200, host.Events.Add); host.Session.TryAcknowledge(Ack(ServerCookie, 3));
            visitor.Session.ProcessData(visitor.Data(8, 0, LocalSessionLeaveChecks.Request()), visitor.Events.Add);
            Check(registry.Count == 1 && visitor.Session.PendingCount == 0, "Visitor could remove host record");
            byte[] leave = host.Data(9, 0, LocalSessionLeaveChecks.Request());
            host.Session.ProcessData(leave, host.Events.Add); host.Session.ProcessData(leave, host.Events.Add);
            Check(registry.Count == 0 && host.Session.PendingCount == 1
                && host.Events.Count(e => e.Event == "local-session-leave-response-queued") == 1,
                "Leave retransmission changed state or queued duplicate response");
            byte[] reply = host.Session.TakeDue(300, host.Events.Add).Single();
            VerifySearchResponse(reply, host.Key, 0x12345678, host.ServerSession, LocalSessionLeaveChecks.Response()); passed++;
            Check(ReferenceEquals(reply, host.Session.TakeDue(1300, host.Events.Add).Single()), "Leave retry changed ciphertext");
            Check(host.Session.TryAcknowledge(Ack(ServerCookie, 4)) && reply.All(b => b == 0), "Leave ACK did not clear reply");
            host.Session.ProcessData(host.Data(10, 0, LocalSessionSearchChecks.Request()), host.Events.Add);
            reply = host.Session.TakeDue(1400, host.Events.Add).Single();
            VerifySearchResponse(reply, host.Key, 0x12345678, host.ServerSession); passed++;
            Check(host.Session.TryAcknowledge(Ack(ServerCookie, 5)), "Search after leave failed");
            host.Session.ProcessData(host.Data(11, 0, LocalSessionCreationChecks.Request()), host.Events.Add);
            reply = host.Session.TakeDue(1500, host.Events.Add).Single();
            VerifySearchResponse(reply, host.Key, 0x12345678, host.ServerSession, LocalSessionCreationChecks.Response(sessionId: 2)); passed++;
            Check(registry.Count == 1 && host.Session.TryAcknowledge(Ack(ServerCookie, 6)), "Recreate after leave failed");
            host.Session.ProcessData(host.Data(12, 0, LocalSessionLeaveChecks.Request()), host.Events.Add);
            Check(registry.Count == 1 && host.Session.PendingCount == 0, "Old leave removed recreated session");
        }
        using (LocalSessionRegistry registry = new(displayProbe: true))
        using (Fixture fixture = new(keepAlive: true, sessions: registry))
        {
            fixture.Register();
            fixture.Session.ProcessData(fixture.Data(8, 0, LocalSessionCreationChecks.Request(body: LocalSessionDisplayChecks.CreateBody())), fixture.Events.Add);
            fixture.Session.TakeDue(200, fixture.Events.Add);
            Check(registry.Count == 1 && fixture.Session.TryAcknowledge(Ack(ServerCookie, 3)), "Display transport create failed");
            fixture.Session.ProcessData(fixture.Data(9, 0, LocalSessionLeaveChecks.Request()), fixture.Events.Add);
            fixture.Session.TakeDue(300, fixture.Events.Add);
            Check(registry.Count == 0 && fixture.Session.TryAcknowledge(Ack(ServerCookie, 4)), "Display transport leave failed");
            byte[] search = LocalSessionDisplayChecks.Search();
            Check(LocalSessionDisplayCodec.TryReply(search, registry, fixture.Session, out var expected, out _), "Display response missing");
            Check(registry.TryCopyDisplaySnapshot(fixture.Session, out var snapshot), "Display transport snapshot missing");
            using (snapshot) { LocalSessionDisplayChecks.Verify(expected, snapshot.Host.ProfileId); passed++; }
            fixture.Session.ProcessData(fixture.Data(10, 0, search), fixture.Events.Add);
            byte[] packet = fixture.Session.TakeDue(400, fixture.Events.Add).Single();
            VerifySearchResponse(packet, fixture.Key, 0x12345678, fixture.ServerSession, expected); passed++;
            Check(fixture.Events.Count(e => e.Reason == "local-session-display-probe-response-created") == 1,
                "Display diagnostic event absent");
            Check(ReferenceEquals(packet, fixture.Session.TakeDue(1400, fixture.Events.Add).Single()), "Display retry changed bytes");
            Check(fixture.Session.TryAcknowledge(Ack(ServerCookie, 5)) && packet.All(b => b == 0), "Display ACK cleanup failed");
            fixture.Session.Dispose();
            Check(!registry.TryCopyDisplaySnapshot(fixture.Session, out _), "Transport teardown retained preview");
            CryptographicOperations.ZeroMemory(expected);
        }
        // Two independently encrypted peers, in both host directions. This tests
        // discovery/Get/reservation/confirmation, not native peer admission or gameplay.
        for (int direction = 0; direction < 10; direction++)
        {
            using LocalSessionRegistry registry = new(catalogueProbe: true);
            using Fixture first = new(keepAlive: true, sessions: registry);
            using Fixture second = new(keepAlive: true, sessions: registry);
            var host = direction % 2 == 0 ? first : second;
            var visitor = direction % 2 == 0 ? second : first;
            var hostRpc = (LocalLoginRpcEngine)typeof(PrudpLocalLoginSession)
                .GetField("rpc", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(host.Session)!;
            // Deterministically exercise signed StationURL serialization in both
            // encrypted host directions, rather than depending on random IDs.
            if (direction >= 2)
                typeof(LocalLoginRpcEngine).GetField("rvConnectionId", BindingFlags.Instance | BindingFlags.NonPublic)!
                    .SetValue(hostRpc, direction % 2 == 0 ? 0x80000000u : 0xffffffffu);
            host.Register(); visitor.Register();
            hostRpc.TryCopyRegisteredPeer(out var registeredHost);
            using var hostPeer = registeredHost;
            bool emptyProfile = direction is 4 or 5 or 8 or 9;
            bool gatewaySentinel = direction >= 6;
            string route = direction < 2 ? LocalSessionDisplayChecks.Route + (direction == 0 ? "" : "#label=fixture")
                : LocalStormRouteChecks.Route(hostPeer.ConnectionId, "10.0.0.1:3074,127.0.0.1:3074", emptyProfile, gatewaySentinel);
            host.Session.ProcessData(host.Data(8, 0, LocalSessionCreationChecks.Request(body: LocalSessionCatalogueChecks.PublicBody(
                route: route))), host.Events.Add);
            host.Session.TakeDue(200, host.Events.Add);
            Check(registry.Count == 1 && host.Session.TryAcknowledge(Ack(ServerCookie, 3)), "Catalogue host create");
            byte[] search = LocalSessionDisplayChecks.Search();
            Check(LocalSessionCatalogueCodec.TrySearch(search, registry, visitor.Session, out var expected, out _), "Catalogue expected snapshot");
            visitor.Session.ProcessData(visitor.Data(8, 0, search), visitor.Events.Add);
            byte[] packet = visitor.Session.TakeDue(300, visitor.Events.Add).Single();
            VerifySearchResponse(packet, visitor.Key, 0x12345678, visitor.ServerSession, expected); passed++;
            Check(visitor.Session.TryAcknowledge(Ack(ServerCookie, 3)) && packet.All(b => b == 0), "Catalogue ACK cleanup");
            CryptographicOperations.ZeroMemory(expected);
            byte[] get = LocalSessionCatalogueChecks.Get();
            Check(LocalSessionCatalogueCodec.TryGet(get, registry, visitor.Session, out expected, out _), "Get expected snapshot");
            visitor.Session.ProcessData(visitor.Data(9, 0, get), visitor.Events.Add);
            packet = visitor.Session.TakeDue(400, visitor.Events.Add).Single();
            VerifySearchResponse(packet, visitor.Key, 0x12345678, visitor.ServerSession, expected); passed++;
            Check(visitor.Session.TryAcknowledge(Ack(ServerCookie, 4)) && packet.All(b => b == 0), "Get ACK cleanup");
            Check(visitor.Events.Any(e => e.Event == "local-session-get-response-queued"), "Get event missing");
            CryptographicOperations.ZeroMemory(expected);
            byte[] joinPacket = visitor.Data(10, 0, LocalSessionJoinChecks.Request());
            visitor.Session.ProcessData(joinPacket, visitor.Events.Add);
            Check(registry.TryCopyLiveSession(visitor.Session, "invented-space"u8, 1, out var pendingJoin), "Join snapshot missing");
            using (pendingJoin)
            {
                Check(pendingJoin.PendingProfiles.Count == 1, "Join did not reserve one member");
                if (direction >= 2)
                    pendingJoin.Metadata.ReplaceCreationRoutes(Encoding.ASCII.GetBytes(LocalStormRouteChecks.Route(hostPeer.ConnectionId, emptyProfile:emptyProfile, gatewaySentinel:gatewaySentinel)));
                expected = LocalSessionJoinCodec.Encode(0x12345678, pendingJoin);
            }
            packet = visitor.Session.TakeDue(450, visitor.Events.Add).Single();
            VerifySearchResponse(packet, visitor.Key, 0x12345678, visitor.ServerSession, expected); passed++;
            visitor.Session.ProcessData(joinPacket, visitor.Events.Add);
            Check(visitor.Session.TryAcknowledge(Ack(ServerCookie, 5)) && packet.All(b => b == 0), "Join ACK cleanup");
            Check(visitor.Events.Count(e => e.Event == "local-session-join-response-queued") == 1, "Duplicate join dispatched twice");
            CryptographicOperations.ZeroMemory(expected);
            visitor.Session.ProcessData(visitor.Data(11, 0, LocalSessionUpdateChecks.Request()), visitor.Events.Add);
            Check(visitor.Session.TakeDue(500, visitor.Events.Add).Count == 0 && registry.Count == 1, "Visitor changed host record");
            visitor.Session.ProcessData(visitor.Data(12, 0, LocalJoinFailureChecks.Request(
                LocalJoinFailureChecks.Body(text:LocalJoinFailureChecks.NativeDescription))), visitor.Events.Add);
            visitor.Session.ProcessData(visitor.Data(13, 0, LocalJoinFailureChecks.Request()), visitor.Events.Add);
            var failure = visitor.Events.Where(e => e.Event == "local-session-join-failure-observed").ToArray();
            Check(failure.Length == 1 && failure[0].ReportedSessionKind == 0
                && failure[0].ReportTextLength == LocalJoinFailureChecks.NativeDescription.Length
                && failure[0].ReportedFailureCategory == "session-request-refused"
                && failure[0].Reason == "local-join-failure-observed", "Encrypted failure report or diagnostic cap");
            string failureJson = System.Text.Json.JsonSerializer.Serialize(failure[0], ConfigServerJsonContext.Default.ConfigServerEvent);
            Check(!failureJson.Contains("private-fixture-text") && !failureJson.Contains(LocalJoinFailureChecks.NativeDescription)
                && failureJson.Contains("reported_session_kind") && failureJson.Contains("session-request-refused")
                && !failureJson.Contains("reported_error_code"), "Failure report redaction and field meaning");
            Check(visitor.Session.TakeDue(550, visitor.Events.Add).Count == 0 && registry.Count == 1, "Diagnostic fabricated reply or removed session");
            // The native game emits this only after its ticket/peer join succeeds.
            // An encrypted RPC retry must return the same void response, without
            // adding another member or granting authority over host settings.
            byte[] success = visitor.Data(14, 0, LocalJoinSuccessChecks.Request());
            visitor.Session.ProcessData(success, visitor.Events.Add);
            packet = visitor.Session.TakeDue(560, visitor.Events.Add).Single();
            VerifySearchResponse(packet, visitor.Key, 0x12345678, visitor.ServerSession, LocalJoinSuccessChecks.Response()); passed++;
            visitor.Session.ProcessData(success, visitor.Events.Add);
            Check(ReferenceEquals(packet, visitor.Session.TakeDue(1560, visitor.Events.Add).Single()), "Confirmation retransmit changed ciphertext");
            Check(visitor.Session.TryAcknowledge(Ack(ServerCookie, 6)) && packet.All(b=>b==0), "Success ACK cleanup");
            Check(visitor.Events.Count(e=>e.Event=="local-session-join-success-response-queued")==1, "Success duplicate dispatch");
            Check(registry.TryCopyLiveSession(host.Session, "invented-space"u8, 1, out var joined), "Encrypted success snapshot");
            using(joined) Check(joined.PendingProfiles.Count==0 && joined.ConfirmedProfiles.Count==1, "Encrypted confirmation membership");
            host.Session.ProcessData(host.Data(9, 0, LocalSessionLeaveChecks.Request()), host.Events.Add);
            host.Session.TakeDue(600, host.Events.Add);
            Check(host.Session.TryAcknowledge(Ack(ServerCookie, 4)) && registry.Count == 0, "Host leave failed");
            visitor.Session.ProcessData(visitor.Data(15, 0, search), visitor.Events.Add);
            packet = visitor.Session.TakeDue(700, visitor.Events.Add).Single();
            VerifySearchResponse(packet, visitor.Key, 0x12345678, visitor.ServerSession); passed++;
            Check(visitor.Session.TryAcknowledge(Ack(ServerCookie, 7)), "Empty-after-leave ACK failed");
        }
        foreach (bool keepAlive in new[] { false, true })
        {
            using LocalSessionRegistry registry = new();
            using Fixture fixture = new(keepAlive: keepAlive, sessions: registry);
            if (!keepAlive) fixture.Register();
            else
            {
                fixture.Login(); fixture.Session.TakeDue(100, fixture.Events.Add); fixture.Session.TryAcknowledge(Ack(ServerCookie, 1));
                fixture.Session.ProcessData(fixture.Data(7, 0, Request(true)), fixture.Events.Add);
            }
            fixture.Session.ProcessData(fixture.Data(8, 0, LocalSessionCreationChecks.Request()), fixture.Events.Add);
            Check(registry.Count == 0 && !fixture.Events.Any(e => e.Event == "local-session-create-response-queued"),
                "Create accepted without opt-in or registration ACK");
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
            byte[] searchPacket = Data(cookie, key, 9, 0, LocalSessionSearchChecks.Request());
            await client.SendAsync(searchPacket);
            firstReceived = await Receive(); secondReceived = await Receive();
            response = firstReceived.Length == 15 ? secondReceived : firstReceived;
            Check(firstReceived.Length == 15 || secondReceived.Length == 15, "Search DATA ACK missing");
            VerifySearchResponse(response, key, 0x12345678, serverSession); passed++;
            await client.SendAsync(Ack(cookie, BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(8))));
            await Wait(() => events.Count(item => item.Event == "local-login-ack-observed" && item.Reason == "response-acknowledged") == 3);
            await client.SendAsync(searchPacket); Check((await Receive()).Length == 15, "Duplicate search DATA not acknowledged");
            await Silence(1200);
            Check(events.Count(item => item.Event == "local-session-search-response-queued") == 1, "Duplicate search created another response");
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
