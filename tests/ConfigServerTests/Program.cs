using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using S7Patcher.Source;

// Isolated synthetic encoder verification: no listeners or production CLI calls.
if (args.Length == 1 && args[0] == "--encoder-only")
{
    Console.WriteLine($"PASS: {PrudpDataPacketEncoderChecks.Run()} isolated DATA encoder checks.");
    return;
}
if (args.Length == 1 && args[0] == "--login-session-only")
{
    Console.WriteLine($"PASS: {LocalLoginSessionChecks.Run()} isolated local login session checks.");
    return;
}
if (args.Length == 1 && args[0] == "--login-network-only")
{
    Console.WriteLine($"PASS: {await LocalLoginSessionChecks.RunNetworkAsync()} local login network checks.");
    return;
}
if (args.Length != 2) throw new ArgumentException("Supply dotnet path and the built S7Patcher.dll path.");
string dotnet = Path.GetFullPath(args[0]);
string patcher = Path.GetFullPath(args[1]);
string scratch = Path.Combine(AppContext.BaseDirectory, "cases-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(scratch);
Directory.SetCurrentDirectory(scratch);
string sentinel = Path.Combine(scratch, "untouched.bin");
File.WriteAllBytes(sentinel, [0x4d, 0x5a, 1, 2, 3, 4]);
string originalHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(sentinel)));
DateTime originalTime = File.GetLastWriteTimeUtc(sentinel);
int passed = 0;
// Invented routing fields and an independently fixed LE-word sum: 0x73ab7230.
byte[] syn = [0x31, 0x3f, 0x00, 0xa7, 0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0x30, 0x72, 0xab, 0x73];
byte[] data = [0x3f, 0x31, 0x02, 0x73, 0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x87, 0xa5, 0xb9, 0xbc, 0xb7];
void Check(bool condition, string message)
{
    if (!condition) throw new Exception(message);
    passed++;
}
async Task WaitUntil(Func<bool> condition, string description)
{
    using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(4));
    while (!condition())
    {
        if (timeout.IsCancellationRequested) throw new Exception("Timed out: " + description);
        await Task.Delay(10);
    }
}
async Task<string> Cli(int expected, params string[] arguments)
{
    ProcessStartInfo start = new(dotnet) { UseShellExecute = false, CreateNoWindow = true,
        RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = scratch };
    start.ArgumentList.Add(patcher);
    foreach (string argument in arguments) start.ArgumentList.Add(argument);
    using Process process = Process.Start(start) ?? throw new Exception("Could not start CLI");
    Task<string> stdout = process.StandardOutput.ReadToEndAsync();
    Task<string> stderr = process.StandardError.ReadToEndAsync();
    using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(12));
    try { await process.WaitForExitAsync(timeout.Token); }
    catch (OperationCanceledException) { process.Kill(); throw new Exception("CLI did not stop within test deadline"); }
    string output = await stdout;
    Check(process.ExitCode == expected, $"CLI expected {expected}, got {process.ExitCode}: {output} {await stderr}");
    return output;
}
string ValidatePublicKey(JsonElement config)
{
    Check(config.EnumerateObject().Select(item => item.Name).Order().SequenceEqual(new[] { "prudp_loadbalancer_url", "prudp_urls", "public_key" }), "Unexpected configuration schema");
    string encoded = config.GetProperty("public_key").GetString()!;
    byte[] blob = Convert.FromBase64String(encoded);
    Check(encoded.Length == 96 && blob.Length == 72, "Public blob is not a 72-byte P-256 blob");
    Check(BinaryPrimitives.ReadUInt32LittleEndian(blob) == 0x31534345 && BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(4)) == 32, "Wrong ECS1 public-key header");
    if (OperatingSystem.IsWindows())
    {
        // Independent Windows CNG parser, not just the blob writer in reverse.
        using CngKey nativeKey = CngKey.Import(blob, CngKeyBlobFormat.EccPublicBlob);
        Check(nativeKey.KeySize == 256 && nativeKey.AlgorithmGroup == CngAlgorithmGroup.ECDsa, "Windows CNG rejected the ECDSA P-256 type");
        using ECDsaCng verifier = new(nativeKey);
        Check(verifier.ExportParameters(false).Q.X!.SequenceEqual(blob.AsSpan(8, 32).ToArray()), "Windows CNG interpreted X differently");
        Check(verifier.ExportParameters(false).Q.Y!.SequenceEqual(blob.AsSpan(40, 32).ToArray()), "Windows CNG interpreted Y differently");
    }
    else
    {
        using ECDsa verifier = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = blob.AsSpan(8, 32).ToArray(), Y = blob.AsSpan(40, 32).ToArray() } });
        Check(verifier.KeySize == 256, "Public point is not importable as P-256");
    }
    return encoded;
}
void VerifyPortsReleased(int httpPort, int udpPort)
{
    TcpListener tcp = new(IPAddress.Loopback, httpPort);
    tcp.Server.ExclusiveAddressUse = true;
    try { tcp.Start(); Check(true, "TCP rebound"); }
    finally { tcp.Stop(); }
    using UdpClient udp = new(AddressFamily.InterNetwork);
    udp.Client.ExclusiveAddressUse = true;
    udp.Client.Bind(new IPEndPoint(IPAddress.Loopback, udpPort));
    Check(true, "UDP rebound");
}

ConcurrentQueue<ConfigServerEvent> events = new();
TaskCompletionSource<ConfigServerEvent> ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
void Record(ConfigServerEvent item) { events.Enqueue(item); if (item.Event == "configuration-server-ready") ready.TrySetResult(item); }
using CancellationTokenSource stop = new();
Task service = LocalConfigurationServer.RunAsync(new() { HttpPort = 0, UdpPort = 0, Seconds = 15 }, Record, stop.Token);
ConfigServerEvent info = await ready.Task.WaitAsync(TimeSpan.FromSeconds(5));
int httpPort = info.HttpPort!.Value, udpPort = info.UdpPort!.Value;
string firstKey;
TcpClient incomplete = new();
try
{
    Check(info.Address == "127.0.0.1" && httpPort > 0 && udpPort > 0, "Listeners are not bound to real loopback ports");
    Check(info.AuthenticationImplemented == false && info.UdpProtocolImplemented == false, "Capabilities must remain explicitly incomplete");
    Check(info.SigningKeyPersistence == "memory-only", "Key lifetime claim changed");
    using HttpClient client = new(new HttpClientHandler { UseProxy = false }) { BaseAddress = new Uri($"http://127.0.0.1:{httpPort}"), Timeout = TimeSpan.FromSeconds(4) };
    using HttpRequestMessage request = new(HttpMethod.Get, LocalConfigurationServer.ConfigurationPath + "?ticket=test-secret-query");
    request.Headers.TryAddWithoutValidation("Authorization", "Bearer test-secret-header");
    request.Headers.TryAddWithoutValidation("Cookie", "test-secret-cookie");
    using HttpResponseMessage response = await client.SendAsync(request);
    Check(response.StatusCode == HttpStatusCode.OK, "Configuration GET failed");
    Check(response.Content.Headers.ContentType?.MediaType == "application/json", "Response is not JSON");
    using JsonDocument document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
    JsonElement config = document.RootElement;
    firstKey = ValidatePublicKey(config);
    Check(config.GetProperty("prudp_loadbalancer_url").GetString() == "", "Load balancer must be empty");
    Check(config.GetProperty("prudp_urls").GetArrayLength() == 1, "Expected exactly one UDP URL");
    Check(config.GetProperty("prudp_urls")[0].GetString() == $"prudp:/address=127.0.0.1;port={udpPort}", "Configuration does not use the actual bound UDP port");
    using JsonDocument repeat = JsonDocument.Parse(await client.GetStringAsync(LocalConfigurationServer.ConfigurationPath));
    Check(repeat.RootElement.GetProperty("public_key").GetString() == firstKey, "Key changed inside a server session");
    using HttpResponseMessage missing = await client.GetAsync("/test-secret-path");
    Check(missing.StatusCode == HttpStatusCode.NotFound, "Unknown route must return 404");
    using HttpResponseMessage method = await client.PostAsync(LocalConfigurationServer.ConfigurationPath, new StringContent("test-secret-body"));
    Check(method.StatusCode == HttpStatusCode.MethodNotAllowed, "Non-GET must return 405");

    using UdpClient sender = new(AddressFamily.InterNetwork);
    sender.Connect(IPAddress.Loopback, udpPort);
    byte[][] packets = [Encoding.ASCII.GetBytes("test-secret-udp-payload"), [], [0, 1, 2], syn, data];
    foreach (byte[] packet in packets) await sender.SendAsync(packet);
    await WaitUntil(() => events.Count(item => item.Event == "udp-datagram-observed") == packets.Length, "UDP counts");
    Check(events.Where(item => item.Event == "udp-datagram-observed").Select(item => item.DatagramLength).SequenceEqual(packets.Select(item => (int?)item.Length)), "Incorrect datagram lengths");
    Check(events.Where(item => item.Event == "udp-datagram-observed").All(item => item.PacketType is null
        && item.ChecksumMatchesZeroSeed is null && item.BytesConsumed is null && item.KnownPeer is null
        && item.ConnectReplySent is null && item.RoutingMatches is null && item.ClientSessionMatches is null
        && item.HeaderCookieMatches is null), "Default mode exposed handshake metadata");
    using CancellationTokenSource noReply = new(TimeSpan.FromMilliseconds(150));
    try { await sender.ReceiveAsync(noReply.Token); throw new Exception("Config-only server must not answer UDP"); }
    catch (OperationCanceledException) { Check(true, "UDP has no protocol response"); }

    using (TcpClient malformed = new())
    {
        await malformed.ConnectAsync(IPAddress.Loopback, httpPort);
        await malformed.GetStream().WriteAsync(Encoding.ASCII.GetBytes("invalid request\r\n\r\n"));
        using StreamReader reader = new(malformed.GetStream());
        Check((await reader.ReadLineAsync()) == "HTTP/1.1 400 Bad Request", "Malformed request must return 400");
    }
    using (TcpClient slow = new())
    {
        await slow.ConnectAsync(IPAddress.Loopback, httpPort);
        await slow.GetStream().WriteAsync(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nX-Test: "));
        byte[] one = new byte[1];
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(4));
        Stopwatch watch = Stopwatch.StartNew();
        int read = await slow.GetStream().ReadAsync(one, timeout.Token);
        Check(read == 0 && watch.Elapsed < TimeSpan.FromSeconds(3), "Incomplete headers did not expire and close promptly");
    }
    await incomplete.ConnectAsync(IPAddress.Loopback, httpPort);
    await incomplete.GetStream().WriteAsync(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n"));
}
finally
{
    stop.Cancel();
    await service.WaitAsync(TimeSpan.FromSeconds(4));
    incomplete.Dispose();
}
Check(events.Last().Event == "configuration-server-stopped", "Stop event preceded handler cleanup");
Check(events.Last().DatagramsReceived == 5 && events.Last().DatagramBytes == Encoding.ASCII.GetByteCount("test-secret-udp-payload") + 3 + syn.Length + data.Length, "Final UDP totals incorrect");
string serialized = string.Join("\n", events.Select(item => JsonSerializer.Serialize(item, ConfigServerJsonContext.Default.ConfigServerEvent)));
Check(!serialized.Contains("test-secret") && !serialized.Contains("Authorization") && !serialized.Contains("Cookie") && !serialized.Contains("ticket="), "Diagnostics leaked request or datagram contents");
Check(!serialized.Contains("packet_type") && !serialized.Contains("checksum_matches_zero_seed") && !serialized.Contains("bytes_consumed"), "Default JSON gained handshake fields");
VerifyPortsReleased(httpPort, udpPort);

// Optional passive decoding: real UDP, invented data, fixed known checksum,
// mismatches remain recognizable, and unknown packets make no checksum claim.
ConcurrentQueue<ConfigServerEvent> metadataEvents = new();
TaskCompletionSource<ConfigServerEvent> metadataReady = new(TaskCreationOptions.RunContinuationsAsynchronously);
using (CancellationTokenSource metadataStop = new())
{
    Task metadataService = LocalConfigurationServer.RunAsync(new() { HttpPort = 0, UdpPort = 0, Seconds = 15,
        HandshakeMetadata = true }, item =>
    {
        metadataEvents.Enqueue(item);
        if (item.Event == "configuration-server-ready") metadataReady.TrySetResult(item);
    }, metadataStop.Token);
    ConfigServerEvent metadataInfo = await metadataReady.Task.WaitAsync(TimeSpan.FromSeconds(4));
    try
    {
        Check(metadataInfo.Message.Contains("hypothesis") && metadataInfo.AuthenticationImplemented == false,
            "Optional mode must not claim a known checksum seed or authentication");
        byte[] badChecksum = (byte[])syn.Clone();
        badChecksum[14] ^= 1;
        byte[] connect = [.. syn.AsSpan(0, 14).ToArray(), .. Encoding.ASCII.GetBytes("test-secret-connect-payload"), 0, 0, 0, 0];
        connect[2] = 1;
        byte[] sized = [.. syn.AsSpan(0, 14).ToArray(), 0, 0, 0x30, 0x72, 0xeb, 0x73,
            .. Encoding.ASCII.GetBytes("test-secret-trailing-bytes")];
        sized[2] = 0x40;
        byte[] badDataChecksum = (byte[])data.Clone(); badDataChecksum[^1] ^= 1;
        byte[][] packets = [syn, badChecksum, connect, [], sized, data, badDataChecksum];
        using UdpClient sender = new(AddressFamily.InterNetwork);
        sender.Connect(IPAddress.Loopback, metadataInfo.UdpPort!.Value);
        foreach (byte[] packet in packets) await sender.SendAsync(packet);
        await WaitUntil(() => metadataEvents.Count(item => item.Event == "udp-datagram-observed") == packets.Length, "Optional UDP metadata");
        ConfigServerEvent[] observed = metadataEvents.Where(item => item.Event == "udp-datagram-observed").ToArray();
        Check(observed[0].PacketType == "syn" && observed[0].ChecksumMatchesZeroSeed == true && observed[0].BytesConsumed == 18,
            "Known 18-byte SYN/zero-seed fixture not recognized");
        Check(observed[1].PacketType == "syn" && observed[1].ChecksumMatchesZeroSeed == false,
            "A checksum mismatch must not hide the structural packet type");
        Check(observed[2].PacketType == "connect" && observed[2].ChecksumMatchesZeroSeed == false && observed[2].BytesConsumed == connect.Length,
            "CONNECT with opaque payload not classified correctly");
        Check(observed[3].PacketType == "unrecognized" && observed[3].ChecksumMatchesZeroSeed is null && observed[3].BytesConsumed is null,
            "Unrecognized input asserted a checksum result or consumed packet");
        Check(observed[4].PacketType == "syn" && observed[4].ChecksumMatchesZeroSeed == true && observed[4].BytesConsumed == 20
            && observed[4].DatagramLength == sized.Length, "Checksum included data beyond declared packet boundary");
        Check(observed[5].PacketType == "data" && observed[5].ChecksumMatchesZeroSeed == true && observed[5].BytesConsumed == 15,
            "Minimum DATA packet was not passively classified");
        Check(observed[6].PacketType == "data" && observed[6].ChecksumMatchesZeroSeed == false,
            "DATA checksum mismatch concealed structural classification");
        string[] allowed = ["event", "datagram_length", "datagrams_received", "udp_protocol_implemented",
            "packet_type", "checksum_matches_zero_seed", "bytes_consumed", "known_peer", "connect_reply_sent",
            "routing_matches", "client_session_matches", "header_cookie_matches"];
        foreach (ConfigServerEvent item in observed)
        {
            string json = JsonSerializer.Serialize(item, ConfigServerJsonContext.Default.ConfigServerEvent);
            using JsonDocument record = JsonDocument.Parse(json);
            Check(record.RootElement.EnumerateObject().All(property => allowed.Contains(property.Name)),
                "UDP metadata exposes a routing, crypto or content field");
            Check(!json.Contains("test-secret"), "Optional metadata leaked packet content");
            Check(item.UdpProtocolImplemented == false, "Metadata implies a working protocol");
        }
        using CancellationTokenSource noReply = new(TimeSpan.FromMilliseconds(150));
        try { await sender.ReceiveAsync(noReply.Token); throw new Exception("Metadata mode answered UDP"); }
        catch (OperationCanceledException) { Check(true, "Metadata mode remains passive"); }
    }
    finally
    {
        metadataStop.Cancel();
        await metadataService.WaitAsync(TimeSpan.FromSeconds(4));
    }
    VerifyPortsReleased(metadataInfo.HttpPort!.Value, metadataInfo.UdpPort!.Value);
}

// A fresh process/session must advertise a fresh key; explicit UDP port must bind.
TaskCompletionSource<ConfigServerEvent> secondReady = new(TaskCreationOptions.RunContinuationsAsynchronously);
Stopwatch bounded = Stopwatch.StartNew();
Task second = LocalConfigurationServer.RunAsync(new() { HttpPort = 0, UdpPort = udpPort, Seconds = 1 }, item =>
{
    if (item.Event == "configuration-server-ready") secondReady.TrySetResult(item);
}, CancellationToken.None);
ConfigServerEvent next = await secondReady.Task.WaitAsync(TimeSpan.FromSeconds(3));
using (HttpClient client = new(new HttpClientHandler { UseProxy = false }))
using (JsonDocument config = JsonDocument.Parse(await client.GetStringAsync($"http://127.0.0.1:{next.HttpPort}{LocalConfigurationServer.ConfigurationPath}")))
{
    Check(ValidatePublicKey(config.RootElement) != firstKey, "A new server session reused its signing key");
    Check(next.UdpPort == udpPort, "Explicit UDP port was ignored");
}
await second.WaitAsync(TimeSpan.FromSeconds(4));
Check(bounded.Elapsed >= TimeSpan.FromMilliseconds(700) && bounded.Elapsed < TimeSpan.FromSeconds(3), "--seconds did not bound the server lifetime");
VerifyPortsReleased(next.HttpPort!.Value, udpPort);

await Cli(2, "--local-config-server=oops");
await Cli(2, "--local-config-server", "--http-port", "-1");
await Cli(2, "--local-config-server", "--http-port", "65536");
await Cli(2, "--local-config-server", "--udp-port", "1", "--udp-port", "2");
await Cli(2, "--local-config-server", "--seconds", "0");
await Cli(2, "--local-config-server", "--unknown", "1");
await Cli(2, "--local-config-server", "--http-port");
await Cli(2, "--local-config-server", "--handshake-metadata", "true");
await Cli(2, "--local-config-server", "--handshake-metadata", "--handshake-metadata");
await Cli(2, "--local-config-server", "--seconds", "--handshake-metadata");
await Cli(2, "--local-config-server", "--syn-probe", "true");
await Cli(2, "--local-config-server", "--syn-probe", "--syn-probe");
await Cli(2, "--local-config-server", "--connect-probe", "true");
await Cli(2, "--local-config-server", "--connect-probe", "--connect-probe");
await Cli(2, "--local-config-server", "--data-ack-probe", "true");
await Cli(2, "--local-config-server", "--data-ack-probe", "--data-ack-probe");
await Cli(2, "--local-config-server", "--data-crypto-probe", "true");
await Cli(2, "--local-config-server", "--data-crypto-probe", "--data-crypto-probe");
await Cli(2, "--local-config-server", "--local-login-probe", "true");
await Cli(2, "--local-config-server", "--local-login-probe", "--local-login-probe");
await Cli(2, "--local-config-server", "--local-keepalive-probe", "--local-keepalive-probe");
await Cli(2, "--local-config-server", "--local-keepalive-probe", "true");
await Cli(2, "--local-config-server", "--local-session-display-probe", "--local-session-display-probe");
await Cli(2, "--local-config-server", "--local-session-display-probe", "true");
string cliOutput = await Cli(0, "--local-config-server", "--http-port", "0", "--udp-port", "0", "--seconds", "1");
Check(cliOutput.Contains("configuration-server-ready") && cliOutput.Contains("configuration-server-stopped"), "CLI server dispatch did not complete");
foreach (string[] options in new string[][] {
    ["--handshake-metadata", "--http-port", "0", "--seconds", "1"],
    ["--http-port", "0", "--handshake-metadata", "--seconds", "1"],
    ["--http-port", "0", "--seconds", "1", "--handshake-metadata"] })
{
    string output = await Cli(0, ["--local-config-server", .. options]);
    Check(output.Contains("Passive SYN/CONNECT/DATA metadata enabled") && output.Contains("configuration-server-stopped"),
        "Boolean metadata switch failed in a supported argument position");
}
using (TcpListener occupied = new(IPAddress.Loopback, 0))
{
    occupied.Server.ExclusiveAddressUse = true;
    occupied.Start();
    await Cli(1, "--local-config-server", "--http-port", ((IPEndPoint)occupied.LocalEndpoint).Port.ToString(), "--seconds", "1");
}
string synOutput = await Cli(0, "--local-config-server", "--http-port", "0", "--syn-probe", "--seconds", "1");
Check(synOutput.Contains("SYN-only loopback probe enabled"), "SYN boolean switch did not enable probe mode");
passed += await PrudpSynProbeChecks.RunAsync();
string connectOutput = await Cli(0, "--local-config-server", "--http-port", "0", "--connect-probe", "--seconds", "1");
Check(connectOutput.Contains("Empty-payload SYN/CONNECT loopback probe enabled"), "CONNECT boolean switch did not enable probe mode");
passed += await PrudpConnectProbeChecks.RunAsync();
string dataAckOutput = await Cli(0, "--local-config-server", "--http-port", "0", "--data-ack-probe", "--seconds", "1");
Check(dataAckOutput.Contains("DATA ACK loopback probe enabled"), "DATA ACK boolean switch did not enable probe mode");
passed += await PrudpDataAckProbeChecks.RunAsync();
string dataCryptoOutput = await Cli(0, "--local-config-server", "--http-port", "0", "--data-crypto-probe", "--seconds", "1");
Check(dataCryptoOutput.Contains("DATA crypto metadata probe enabled"), "DATA crypto boolean switch did not enable probe mode");
passed += await PrudpDataCryptoProbeChecks.RunAsync();
passed += PrudpDataPacketEncoderChecks.Run();
string loginOutput = await Cli(0, "--local-config-server", "--http-port", "0", "--local-login-probe", "--seconds", "1");
Check(loginOutput.Contains("Experimental local Login/Register responses enabled"), "Local login boolean switch did not enable probe mode");
passed += LocalSessionSearchChecks.Run();
passed += LocalSessionDisplayChecks.Run();
passed += LocalSessionCatalogueChecks.Run();
passed += LocalNetworkPolicyChecks.Run();
passed += LocalSessionJoinShapeChecks.Run();
passed += LocalSessionCreationChecks.Run();
passed += RegisteredHostChecks.Run();
passed += CreationFieldChecks.Run();
passed += ReliableResponseQueueChecks.Run();
passed += LocalSessionUpdateChecks.Run();
passed += LocalSessionLeaveChecks.Run();
passed += LocalLoginSessionChecks.Run();
await Cli(0, "--local-config-server", "--http-port", "0", "--local-keepalive-probe", "--seconds", "1");
string displayOutput = await Cli(0, "--local-config-server", "--http-port", "0", "--local-session-display-probe", "--seconds", "1");
Check(displayOutput.Contains("Display probe:", StringComparison.Ordinal), "Display mode not disclosed by CLI");
await Cli(2, "--local-config-server", "--local-catalogue-probe", "--local-session-display-probe");
await Cli(2, "--local-config-server", "--local-catalogue-probe", "--local-catalogue-probe");
string catalogueOutput = await Cli(0, "--local-config-server", "--http-port", "0", "--local-catalogue-probe", "--seconds", "1");
Check(catalogueOutput.Contains("Public catalogue candidate:", StringComparison.Ordinal), "Catalogue mode not disclosed by CLI");
await Cli(2, "--local-config-server", "--local-catalogue-probe", "--lan-address", "192.168.10.10");
await Cli(2, "--local-config-server", "--local-catalogue-probe", "--lan-address", "192.168.10.10", "--lan-peer", "8.8.8.8");
await Cli(2, "--local-config-server", "--lan-address", "192.168.10.10", "--lan-peer", "192.168.10.20");
passed += await LocalLoginSessionChecks.RunNetworkAsync();
Check(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(sentinel))) == originalHash && File.GetLastWriteTimeUtc(sentinel) == originalTime, "Server modified an existing file");
Check(Directory.GetFileSystemEntries(scratch).SequenceEqual(new[] { sentinel }), "Server persisted a key, configuration or log file");
Console.WriteLine($"PASS: {passed} config-server checks; real HTTP/UDP, Windows CNG import where supported, redacted logs, lifetime/cleanup, CLI and file immutability.");
