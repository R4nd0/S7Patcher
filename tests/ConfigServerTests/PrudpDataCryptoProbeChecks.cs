using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using S7Patcher.Source;

internal static class PrudpDataCryptoProbeChecks
{
    private static readonly byte[] FixtureIv = Enumerable.Range(0, 16).Select(value => (byte)value).ToArray();
    private const ushort Sequence = 0x4567;

    private static void Sum(byte[] packet)
    {
        uint sum = 0;
        for (int index = 0; index < packet.Length - 4; index++)
            sum = unchecked(sum + ((uint)packet[index] << ((index % 4) * 8)));
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(packet.Length - 4), sum);
    }

    private static byte[] Connect(uint cookie, ECDiffieHellman client)
    {
        ECParameters point = client.ExportParameters(false);
        byte[] packet = new byte[92];
        packet[0] = 0x3a; packet[1] = 0x31; packet[2] = 0xb1; packet[3] = 0x53;
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(4), cookie);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(8), 0x1234);
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(10), 0x12345678);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(14), 72);
        new byte[] { 0x45, 0x43, 0x4b, 0x31, 32, 0, 0, 0 }.CopyTo(packet, 16);
        point.Q.X!.CopyTo(packet, 24); point.Q.Y!.CopyTo(packet, 56); Sum(packet);
        return packet;
    }

    private static byte[] Data(uint cookie, byte[] body, ushort sequence = Sequence)
    {
        byte[] packet = new byte[15 + body.Length];
        packet[0] = 0x3a; packet[1] = 0x31; packet[2] = 0x32; packet[3] = 0x53;
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(4), cookie);
        BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(8), sequence);
        packet[10] = 7; body.CopyTo(packet, 11); Sum(packet); return packet;
    }

    private static byte[] Envelope(byte[] content, bool compressed, byte hint = 1)
    {
        if (!compressed) return [0, .. content];
        // ZLibStream may emit nothing when Write receives no input; this is an
        // explicit complete empty zlib stream (final empty block + Adler32=1).
        if (content.Length == 0) return [hint, 0x78, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01];
        using MemoryStream output = new();
        output.WriteByte(hint);
        using (ZLibStream zlib = new(output, CompressionLevel.SmallestSize, true)) zlib.Write(content);
        return output.ToArray();
    }

    private static byte[] Encrypt(byte[] envelope, byte[] key) =>
        [.. FixtureIv, .. NativeCngFixtures.Encrypt(envelope, key, FixtureIv)];

    internal static async Task<int> RunAsync()
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.WriteLine("SKIP: independent BCrypt DATA crypto interoperability requires Windows.");
            return 0;
        }
        int passed = 0;
        void Check(bool condition, string message) { if (!condition) throw new Exception(message); passed++; }
        using ECDiffieHellman client = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa signing = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        const uint serverCookie = 0xabcdef01;
        byte[] connect = Connect(serverCookie, client);
        Check(PrudpConnectProbe.TryReadRequest(connect, serverCookie, 0x3a, out var metadata, out _), "Crypto fixture CONNECT invalid");
        using PrudpProbePeer peer = new() { Cookie = serverCookie, SourceVirtualPort = 0x3a, SynReplySent = true,
            ConnectReplySent = true, Connect = new PrudpConnectProbe(connect, metadata, signing) };
        Check(peer.Connect.TryGetReply(connect, metadata, out byte[] reply), "No fixture CONNECT reply");
        byte[] nativeKey = NativeCngFixtures.Derive(client, reply.AsSpan(82, 72).ToArray());
        byte[] managedKey = peer.Connect.DeriveDataKey();
        try
        {
            Check(nativeKey.Length == 16 && CryptographicOperations.FixedTimeEquals(nativeKey, managedKey),
                "Actual BCrypt HASH/NULL/16 KDF differs from managed SHA1 first16");
            // Both directions use native BCrypt with BCRYPT_BLOCK_PADDING, including
            // empty plaintext and exact AES-block boundaries. No managed mirror oracle.
            using Aes aes = Aes.Create(); aes.SetKey(managedKey);
            foreach (int length in new[] { 0, 1, 15, 16, 17, 31, 32, 33 })
            {
                byte[] plain = Enumerable.Range(0, length).Select(value => (byte)value).ToArray();
                byte[] nativeCipher = NativeCngFixtures.Encrypt(plain, nativeKey, FixtureIv);
                byte[] managedPlain = aes.DecryptCbc(nativeCipher, FixtureIv, PaddingMode.PKCS7);
                byte[] managedCipher = aes.EncryptCbc(plain, FixtureIv, PaddingMode.PKCS7);
                byte[] nativePlain = NativeCngFixtures.Decrypt(managedCipher, nativeKey, FixtureIv);
                Check(nativeCipher.Length == ((length / 16) + 1) * 16 && managedPlain.SequenceEqual(plain), "Native CBC padding incompatible with managed PKCS7");
                Check(nativePlain.SequenceEqual(plain), "Managed PKCS7 incompatible with native CBC padding");
                CryptographicOperations.ZeroMemory(plain); CryptographicOperations.ZeroMemory(managedPlain); CryptographicOperations.ZeroMemory(nativePlain);
            }
            byte[] content = [.. Encoding.ASCII.GetBytes("test-secret-crypto-plaintext"), 0x67, 0x45];
            foreach ((bool compressed, byte hint) in new (bool, byte)[] { (false, 0), (true, 1), (true, 255) })
            {
                byte[] envelope = Envelope(content, compressed, hint);
                byte[] packet = Data(serverCookie, Encrypt(envelope, nativeKey));
                byte[] original = SHA256.HashData(packet);
                var result = PrudpDataCryptoProbe.Inspect(packet, peer);
                Check(result.Outcome == "decoded-sequence-matched" && result.SequenceMatches == true && result.Compressed == compressed
                    && result.DecodedPayloadLength == content.Length - 2 && result.DecryptedEnvelopeLength == envelope.Length,
                    "Native encrypted flat/zlib fixture not decoded correctly");
                Check(SHA256.HashData(packet).SequenceEqual(original), "Crypto inspection mutated original DATA bytes");
                packet[10]++; Sum(packet);
                Check(PrudpDataCryptoProbe.Inspect(packet, peer).SequenceMatches == true, "Part byte incorrectly participates in AES/sequence binding");
                packet[8] ^= 1; Sum(packet);
                Check(PrudpDataCryptoProbe.Inspect(packet, peer).Outcome == "sequence-mismatch", "Wrong header sequence accepted after decompression");
                packet[3] ^= 1; Sum(packet);
                Check(PrudpDataCryptoProbe.Inspect(packet, peer).Outcome == "outside-data-crypto-context", "Wrong peer session decrypted");
                CryptographicOperations.ZeroMemory(envelope);
            }
            PrudpDataCryptoResult InspectEnvelope(byte[] envelope, ushort sequence = Sequence) =>
                PrudpDataCryptoProbe.InspectBody(Encrypt(envelope, nativeKey), sequence, managedKey);
            Check(InspectEnvelope([]).Outcome == "missing-compression-envelope", "Empty decrypted data accepted");
            Check(InspectEnvelope([0]).Outcome == "missing-sequence-suffix", "Missing sequence accepted");
            Check(InspectEnvelope([0, 0x67]).Outcome == "missing-sequence-suffix", "One-byte sequence accepted");
            Check(InspectEnvelope([0, 0x67, 0x45]).DecodedPayloadLength == 0, "Empty application data plus valid suffix rejected");
            Check(PrudpDataCryptoProbe.Inspect(Data(serverCookie, []), peer).Outcome == "empty-body-bypassed", "Empty wire body claimed decryption");
            foreach (int length in new[] { 1, 15, 16, 17, 31, 33, 65508 })
                Check(PrudpDataCryptoProbe.InspectBody(new byte[length], Sequence, managedKey).Outcome == "invalid-cbc-length", "Invalid CBC body length accepted");
            Check(PrudpDataCryptoProbe.InspectBody(new byte[32], Sequence, new byte[32]).Outcome == "invalid-key-length", "Non-AES128 key accepted");
            byte[] padding = Encrypt([0], nativeKey); padding[15] ^= 0x0f;
            Check(PrudpDataCryptoProbe.InspectBody(padding, Sequence, managedKey).Outcome == "cbc-padding-or-decryption-failed", "Invalid native CBC padding accepted");
            byte[] zlibEnvelope = Envelope(content, true);
            foreach (byte[] malformed in new byte[][] {
                zlibEnvelope[..^1], zlibEnvelope[..^4], [1, 0x78, 0x01],
                // Nonfinal DEFLATE block with correct Adler32: ordinary .NET EOF
                // accepts it, but the native Z_STREAM_END contract must reject it.
                [1, 0x78, 0x01, 0x00, 0x02, 0x00, 0xfd, 0xff, 0x01, 0x00, 0x00, 0x04, 0x00, 0x02] })
                Check(InspectEnvelope(malformed, 1).Outcome == "zlib-invalid-or-incomplete", "Incomplete zlib stream accepted");
            zlibEnvelope[^1] ^= 1;
            Check(InspectEnvelope(zlibEnvelope).Outcome == "zlib-invalid-or-incomplete", "Corrupt zlib trailer accepted");
            foreach (int decodedLength in new[] { 0, 1, 2, 16, 4096, PrudpDataCryptoProbe.PlaintextLimit })
            {
                byte[] decoded = new byte[decodedLength];
                if (decoded.Length >= 2) BinaryPrimitives.WriteUInt16LittleEndian(decoded.AsSpan(decoded.Length - 2), Sequence);
                var result = InspectEnvelope(Envelope(decoded, true));
                Check(result.Outcome == (decodedLength < 2 ? "missing-sequence-suffix" : "decoded-sequence-matched"), "Valid zlib stream rejected near output boundary");
                CryptographicOperations.ZeroMemory(decoded);
            }
            Stopwatch bombTime = Stopwatch.StartNew();
            Check(InspectEnvelope(Envelope(new byte[1024 * 1024], true)).Outcome == "decompression-limit-exceeded", "Inflate output escaped conservative cap");
            Check(bombTime.Elapsed < TimeSpan.FromSeconds(5), "Bounded compression fixture exceeded generous deadline");
            byte[] badChecksum = Data(serverCookie, Encrypt([0, 0x67, 0x45], nativeKey)); badChecksum[^1] ^= 1;
            Check(PrudpDataCryptoProbe.Inspect(badChecksum, peer).Outcome == "outside-data-crypto-context", "Invalid checksum decrypted");
            peer.ConnectReplySent = false;
            Check(PrudpDataCryptoProbe.Inspect(Data(serverCookie, Encrypt([0, 0x67, 0x45], nativeKey)), peer).Outcome == "outside-data-crypto-context", "Unsent CONNECT enabled crypto");
            peer.ConnectReplySent = true;
            CryptographicOperations.ZeroMemory(content);
        }
        finally { CryptographicOperations.ZeroMemory(nativeKey); CryptographicOperations.ZeroMemory(managedKey); }

        ConcurrentQueue<ConfigServerEvent> events = new();
        TaskCompletionSource<ConfigServerEvent> ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenSource stop = new();
        Task service = LocalConfigurationServer.RunAsync(new() { HttpPort = 0, UdpPort = 0, DataCryptoProbe = true, Seconds = 20 }, item =>
        { events.Enqueue(item); if (item.Event == "configuration-server-ready") ready.TrySetResult(item); }, stop.Token);
        ConfigServerEvent info = await ready.Task.WaitAsync(TimeSpan.FromSeconds(4));
        using UdpClient sender = new(AddressFamily.InterNetwork);
        sender.Connect(IPAddress.Loopback, info.UdpPort!.Value);
        async Task<byte[]> Exchange(byte[] packet)
        {
            await sender.SendAsync(packet);
            using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(2));
            return (await sender.ReceiveAsync(deadline.Token)).Buffer;
        }
        byte[] liveKey = null;
        try
        {
            byte[] syn = new byte[18]; syn[0] = 0x3a; syn[1] = 0x31; syn[2] = 0x20; Sum(syn);
            uint cookie = BinaryPrimitives.ReadUInt32LittleEndian((await Exchange(syn)).AsSpan(10));
            byte[] ack = await Exchange(Connect(cookie, client));
            Check(ack.Length == 158, "Crypto mode did not imply handshake probes");
            liveKey = NativeCngFixtures.Derive(client, ack.AsSpan(82, 72).ToArray());
            foreach (bool compressed in new[] { false, true })
            {
                byte[] content = [.. Encoding.ASCII.GetBytes("test-secret-live-crypto"), 0x67, 0x45];
                byte[] envelope = Envelope(content, compressed);
                byte[] dataAck = await Exchange(Data(cookie, Encrypt(envelope, liveKey)));
                Check(dataAck.Length == 15 && dataAck[2] == 0x0a, "Crypto mode produced an application reply instead of DATA ACK");
                CryptographicOperations.ZeroMemory(content); CryptographicOperations.ZeroMemory(envelope);
            }
            Check((await Exchange(Data(cookie, [1]))).Length == 15, "Native ACK-before-decrypt order changed");
            Check((await Exchange(Data(cookie, []))).Length == 15, "Empty body bypass changed ACK behavior");
            using CancellationTokenSource noApplicationReply = new(TimeSpan.FromMilliseconds(150));
            try { await sender.ReceiveAsync(noApplicationReply.Token); throw new Exception("Unexpected reply after transport ACK"); }
            catch (OperationCanceledException) { passed++; }
            int prior = events.Count(item => item.Event == "data-crypto-probe-observed");
            await sender.SendAsync(Data(unchecked(cookie + 1), Encrypt([0, 0x67, 0x45], liveKey)));
            using CancellationTokenSource mismatchDeadline = new(TimeSpan.FromMilliseconds(150));
            try { await sender.ReceiveAsync(mismatchDeadline.Token); throw new Exception("Wrong cookie received response"); }
            catch (OperationCanceledException) { passed++; }
            Check(events.Count(item => item.Event == "data-crypto-probe-observed") == prior, "Wrong-context DATA reached crypto processing");
        }
        finally
        {
            if (liveKey != null) CryptographicOperations.ZeroMemory(liveKey);
            stop.Cancel(); await service.WaitAsync(TimeSpan.FromSeconds(4));
        }
        var cryptoEvents = events.Where(item => item.Event == "data-crypto-probe-observed").ToArray();
        Check(cryptoEvents.Length == 4 && cryptoEvents.Count(item => item.Reason == "decoded-sequence-matched") == 2,
            "Loopback native-encrypted fixtures not decoded or attempts counted incorrectly");
        Check(cryptoEvents.Any(item => item.Reason == "invalid-cbc-length") && cryptoEvents.Any(item => item.Reason == "empty-body-bypassed"), "Failure/bypass outcomes missing");
        string[] allowed = ["event", "elapsed_milliseconds", "reason", "serialized_payload_length", "decrypted_envelope_length", "decoded_payload_length",
            "compressed", "sequence_matches", "authentication_implemented", "udp_protocol_implemented"];
        foreach (var item in cryptoEvents)
        {
            string json = JsonSerializer.Serialize(item, ConfigServerJsonContext.Default.ConfigServerEvent);
            using JsonDocument document = JsonDocument.Parse(json);
            Check(document.RootElement.EnumerateObject().All(property => allowed.Contains(property.Name)) && !json.Contains("test-secret"), "Crypto log exposed non-metadata fields/content");
            Check(item.AuthenticationImplemented == false && item.UdpProtocolImplemented == false, "Crypto metadata claims login or full protocol");
        }
        Check(events.Last().Event == "configuration-server-stopped", "Crypto service did not drain before stop event");
        using (TcpListener rebound = new(IPAddress.Loopback, info.HttpPort!.Value))
        { rebound.Server.ExclusiveAddressUse = true; rebound.Start(); passed++; }
        using (UdpClient rebound = new(AddressFamily.InterNetwork))
        { rebound.Client.ExclusiveAddressUse = true; rebound.Client.Bind(new IPEndPoint(IPAddress.Loopback, info.UdpPort!.Value)); passed++; }
        return passed;
    }
}
