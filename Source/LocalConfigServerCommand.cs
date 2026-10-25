using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace S7Patcher.Source
{
    internal static class LocalConfigServerCommand
    {
        internal static bool TryRun(string[] args, out int exitCode)
        {
            exitCode = 0;
            if (!args.Any(value => value.StartsWith("--local-config-server", StringComparison.OrdinalIgnoreCase)))
                return false;
            object outputLock = new();
            void Emit(ConfigServerEvent record)
            {
                lock (outputLock)
                    Console.WriteLine(JsonSerializer.Serialize(record, ConfigServerJsonContext.Default.ConfigServerEvent));
            }
            if (!TryParse(args, out LocalConfigServerOptions options))
            {
                Emit(new() { Event = "configuration-server-error", Reason = "invalid-arguments",
                    Message = "Usage: S7Patcher --local-config-server [--http-port 0..65535] [--udp-port 0..65535] [--seconds 1..86400] [--handshake-metadata] [--syn-probe]" });
                exitCode = 2;
                return true;
            }
            using CancellationTokenSource stop = new();
            ConsoleCancelEventHandler cancel = (_, input) => { input.Cancel = true; stop.Cancel(); };
            Console.CancelKeyPress += cancel;
            try
            {
                LocalConfigurationServer.RunAsync(options, Emit, stop.Token).GetAwaiter().GetResult();
            }
            catch (Exception exception) when (exception is SocketException || exception is IOException
                || exception is CryptographicException || exception is UnauthorizedAccessException)
            {
                // Exception text can contain endpoint details. Report only a fixed category.
                Emit(new() { Event = "configuration-server-error", Reason = "local-bind-key-or-io-failure" });
                exitCode = 1;
            }
            finally
            {
                Console.CancelKeyPress -= cancel;
            }
            return true;
        }

        private static bool TryParse(string[] args, out LocalConfigServerOptions options)
        {
            options = new();
            if (args.Length == 0 || args[0] != "--local-config-server")
                return false;
            HashSet<string> seen = new(StringComparer.Ordinal);
            for (int index = 1; index < args.Length; index++)
            {
                string name = args[index];
                if (!seen.Add(name)) return false;
                if (name == "--handshake-metadata")
                {
                    options.HandshakeMetadata = true;
                    continue;
                }
                if (name == "--syn-probe")
                {
                    options.SynProbe = true;
                    options.HandshakeMetadata = true;
                    continue;
                }
                if (++index >= args.Length || !int.TryParse(args[index], NumberStyles.None, CultureInfo.InvariantCulture, out int value))
                    return false;
                switch (name)
                {
                    case "--http-port" when value <= 65535: options.HttpPort = value; break;
                    case "--udp-port" when value <= 65535: options.UdpPort = value; break;
                    case "--seconds" when value is >= 1 and <= 86400: options.Seconds = value; break;
                    default: return false;
                }
            }
            return true;
        }
    }

    internal sealed class LocalConfigServerOptions
    {
        public int HttpPort { get; set; } = 9110;
        public int UdpPort { get; set; } = 0;
        public int? Seconds { get; set; }
        public bool HandshakeMetadata { get; set; }
        public bool SynProbe { get; set; }
    }

    internal static class LocalConfigurationServer
    {
        internal const string ConfigurationPath = "/public/rendezvous/v1/configuration";
        private const int HeaderLimit = 32768;
        private const int FirstLineLimit = 2048;
        private const int ConcurrentRequestLimit = 8;

        internal static async Task RunAsync(LocalConfigServerOptions options, Action<ConfigServerEvent> emit, CancellationToken cancellation)
        {
            using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            if (options.Seconds.HasValue) stop.CancelAfter(TimeSpan.FromSeconds(options.Seconds.Value));
            // The private key exists only for this process lifetime and is never exported.
            using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using UdpClient udp = new(AddressFamily.InterNetwork);
            udp.Client.ExclusiveAddressUse = true;
            TcpListener http = new(IPAddress.Loopback, options.HttpPort);
            http.Server.ExclusiveAddressUse = true;
            long datagrams = 0;
            long datagramBytes = 0;
            // Sender endpoints and cookies are process-local, bounded and never logged.
            Dictionary<IPEndPoint, uint> synCookies = new();
            try
            {
                udp.Client.Bind(new IPEndPoint(IPAddress.Loopback, options.UdpPort));
                int udpPort = ((IPEndPoint)udp.Client.LocalEndPoint).Port;
                http.Start(16);
                int httpPort = ((IPEndPoint)http.LocalEndpoint).Port;
                byte[] response = JsonSerializer.SerializeToUtf8Bytes(new LocalServerConfiguration
                {
                    PublicKey = ExportPublicBlob(key),
                    PrudpLoadbalancerUrl = "",
                    PrudpUrls = ["prudp:/address=127.0.0.1;port=" + udpPort.ToString(CultureInfo.InvariantCulture)]
                }, ConfigServerJsonContext.Default.LocalServerConfiguration);
                emit(new()
                {
                    Event = "configuration-server-ready", Address = "127.0.0.1", HttpPort = httpPort, UdpPort = udpPort,
                    ConfigurationPath = ConfigurationPath, AuthenticationImplemented = false, UdpProtocolImplemented = false,
                    SigningKeyPersistence = "memory-only",
                    Message = options.SynProbe
                        ? "SYN-only loopback probe enabled; zero checksum seed is a hypothesis. No CONNECT response or authentication."
                        : options.HandshakeMetadata
                        ? "Configuration endpoint only. Passive SYN/CONNECT metadata enabled; zero checksum seed is a hypothesis, not authentication. No UDP replies."
                        : "Configuration endpoint only. UDP datagrams are counted; no authentication or game protocol is implemented."
                });

                Task httpTask = AcceptRequestsAsync(http, response, emit, stop.Token);
                Task udpTask = ObserveDatagramsAsync();
                try
                {
                    // A failed loop must also stop the other loop, even without --seconds.
                    await Task.WhenAny(httpTask, udpTask);
                }
                finally
                {
                    stop.Cancel();
                    http.Stop();
                    udp.Dispose();
                    await Task.WhenAll(httpTask, udpTask);
                }

                async Task ObserveDatagramsAsync()
                {
                    try
                    {
                        while (!stop.IsCancellationRequested)
                        {
                            UdpReceiveResult packet = await udp.ReceiveAsync(stop.Token);
                            // Default: lengths only. Optional decoding never logs content,
                            // routing fields, crypto material or the remote endpoint.
                            int length = packet.Buffer.Length;
                            Interlocked.Increment(ref datagrams);
                            Interlocked.Add(ref datagramBytes, length);
                            ConfigServerEvent observation = new() { Event = "udp-datagram-observed", DatagramLength = length,
                                DatagramsReceived = Interlocked.Read(ref datagrams), UdpProtocolImplemented = false };
                            if (options.HandshakeMetadata || options.SynProbe)
                            {
                                observation.PacketType = "unrecognized";
                                // First decode structurally without asserting an established seed.
                                if (PrudpHandshakePacketDecoder.TryDecode(packet.Buffer, out PrudpHandshakeMetadata decoded, out _))
                                {
                                    observation.PacketType = decoded.Type == PrudpHandshakePacketType.Syn ? "syn" : "connect";
                                    observation.BytesConsumed = decoded.BytesConsumed;
                                    observation.ChecksumMatchesZeroSeed = PrudpHandshakePacketDecoder.ComputeChecksum(
                                        packet.Buffer.AsSpan(0, decoded.BytesConsumed - 4), 0) == decoded.Checksum;
                                }
                            }
                            emit(observation);
                            if (options.SynProbe && IPAddress.IsLoopback(packet.RemoteEndPoint.Address)
                                && PrudpSynProbeCodec.TryReadRequest(packet.Buffer, out PrudpHandshakeMetadata syn))
                            {
                                if (!synCookies.TryGetValue(packet.RemoteEndPoint, out uint cookie))
                                {
                                    if (synCookies.Count >= 8) continue;
                                    byte[] random = new byte[4];
                                    do
                                    {
                                        RandomNumberGenerator.Fill(random);
                                        cookie = BinaryPrimitives.ReadUInt32LittleEndian(random);
                                    } while (cookie == 0);
                                    synCookies.Add(packet.RemoteEndPoint, cookie);
                                }
                                byte[] reply = PrudpSynProbeCodec.CreateReply(syn, cookie);
                                await udp.SendAsync(reply, packet.RemoteEndPoint, stop.Token);
                                emit(new() { Event = "syn-probe-reply-sent", DatagramLength = reply.Length,
                                    AuthenticationImplemented = false, UdpProtocolImplemented = false });
                            }
                        }
                    }
                    catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
                    catch (ObjectDisposedException) when (stop.IsCancellationRequested) { }
                    catch (SocketException) when (stop.IsCancellationRequested) { }
                }
            }
            finally
            {
                http.Stop();
                udp.Dispose();
                synCookies.Clear();
                emit(new() { Event = "configuration-server-stopped", DatagramsReceived = Interlocked.Read(ref datagrams),
                    DatagramBytes = Interlocked.Read(ref datagramBytes) });
            }
        }

        private static string ExportPublicBlob(ECDsa key)
        {
            ECParameters parameters = key.ExportParameters(false);
            if (parameters.Q.X?.Length != 32 || parameters.Q.Y?.Length != 32)
                throw new CryptographicException("Unexpected P-256 public point size");
            byte[] blob = new byte[72];
            BinaryPrimitives.WriteUInt32LittleEndian(blob, 0x31534345); // BCRYPT_ECDSA_PUBLIC_P256_MAGIC, "ECS1"
            BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(4), 32);
            parameters.Q.X.CopyTo(blob, 8);
            parameters.Q.Y.CopyTo(blob, 40);
            return Convert.ToBase64String(blob);
        }

        private static async Task AcceptRequestsAsync(TcpListener listener, byte[] configuration, Action<ConfigServerEvent> emit, CancellationToken stop)
        {
            using SemaphoreSlim slots = new(ConcurrentRequestLimit);
            List<Task> requests = [];
            try
            {
                while (!stop.IsCancellationRequested)
                {
                    for (int index = requests.Count - 1; index >= 0; index--)
                    {
                        if (!requests[index].IsCompleted) continue;
                        await requests[index];
                        requests.RemoveAt(index);
                    }
                    await slots.WaitAsync(stop);
                    TcpClient client;
                    try { client = await listener.AcceptTcpClientAsync(stop); }
                    catch { slots.Release(); throw; }
                    requests.Add(ServeAndReleaseAsync(client));
                }
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
            catch (ObjectDisposedException) when (stop.IsCancellationRequested) { }
            catch (SocketException) when (stop.IsCancellationRequested) { }
            finally
            {
                await Task.WhenAll(requests);
            }

            async Task ServeAndReleaseAsync(TcpClient client)
            {
                try { await ServeRequestAsync(client, configuration, emit, stop); }
                finally { slots.Release(); }
            }
        }

        private static async Task ServeRequestAsync(TcpClient client, byte[] configuration, Action<ConfigServerEvent> emit, CancellationToken stop)
        {
            using (client)
            using (CancellationTokenSource deadline = CancellationTokenSource.CreateLinkedTokenSource(stop))
            {
                deadline.CancelAfter(TimeSpan.FromSeconds(2));
                int count = 0;
                try
                {
                    NetworkStream stream = client.GetStream();
                    byte[] one = new byte[1];
                    byte[] firstLine = new byte[FirstLineLimit + 1];
                    int firstLength = 0;
                    bool firstDone = false;
                    uint ending = 0;
                    bool headerComplete = false;
                    while (count < HeaderLimit)
                    {
                        if (await stream.ReadAsync(one.AsMemory(), deadline.Token) == 0)
                            throw new IOException("Incomplete request");
                        byte current = one[0];
                        count++;
                        if (!firstDone)
                        {
                            if (firstLength < firstLine.Length) firstLine[firstLength++] = current;
                            if (current == 10) firstDone = true;
                        }
                        ending = unchecked((ending << 8) | current);
                        if (ending == 0x0d0a0d0a || (ending & 0xffff) == 0x0a0a)
                        {
                            headerComplete = true;
                            break;
                        }
                    }
                    // Only the request line is interpreted. Header values and body bytes are never retained or logged.
                    int status = 400;
                    if (!headerComplete) status = 431;
                    else if (firstDone && firstLength <= FirstLineLimit)
                    {
                        string[] pieces = Encoding.ASCII.GetString(firstLine, 0, firstLength).TrimEnd('\r', '\n').Split(' ');
                        if (pieces.Length == 3 && (pieces[2] == "HTTP/1.1" || pieces[2] == "HTTP/1.0"))
                        {
                            if (pieces[0] != "GET") status = 405;
                            else status = pieces[1].Split('?', 2)[0] == ConfigurationPath ? 200 : 404;
                        }
                    }
                    byte[] body = status == 200 ? configuration : [];
                    string reason = status switch { 200 => "OK", 404 => "Not Found", 405 => "Method Not Allowed", 431 => "Request Header Fields Too Large", _ => "Bad Request" };
                    string headers = "HTTP/1.1 " + status.ToString(CultureInfo.InvariantCulture) + " " + reason + "\r\n"
                        + "Content-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\n"
                        + (status == 405 ? "Allow: GET\r\n" : "")
                        + "Content-Length: " + body.Length.ToString(CultureInfo.InvariantCulture) + "\r\n\r\n";
                    byte[] encodedHeaders = Encoding.ASCII.GetBytes(headers);
                    byte[] response = new byte[encodedHeaders.Length + body.Length];
                    encodedHeaders.CopyTo(response, 0);
                    body.CopyTo(response, encodedHeaders.Length);
                    // Send a complete response together. Empty error bodies avoid
                    // losing a trailing write when a rejected request has a body.
                    await stream.WriteAsync(response, deadline.Token);
                    client.Client.Shutdown(SocketShutdown.Send);
                    emit(new() { Event = "configuration-http-response", Status = status, RequestBytesRead = count });
                }
                catch (OperationCanceledException) when (deadline.IsCancellationRequested)
                {
                    emit(new() { Event = "configuration-http-incomplete", RequestBytesRead = count });
                }
                catch (IOException) { emit(new() { Event = "configuration-http-incomplete", RequestBytesRead = count }); }
                catch (SocketException) { emit(new() { Event = "configuration-http-incomplete", RequestBytesRead = count }); }
            }
        }
    }

    internal sealed class LocalServerConfiguration
    {
        public string PublicKey { get; set; }
        public string PrudpLoadbalancerUrl { get; set; }
        public string[] PrudpUrls { get; set; }
    }

    internal sealed class ConfigServerEvent
    {
        public string Event { get; set; }
        public string Reason { get; set; }
        public string Message { get; set; }
        public string Address { get; set; }
        public int? HttpPort { get; set; }
        public int? UdpPort { get; set; }
        public string ConfigurationPath { get; set; }
        public bool? AuthenticationImplemented { get; set; }
        public bool? UdpProtocolImplemented { get; set; }
        public string SigningKeyPersistence { get; set; }
        public int? DatagramLength { get; set; }
        public long? DatagramsReceived { get; set; }
        public long? DatagramBytes { get; set; }
        public string PacketType { get; set; }
        public bool? ChecksumMatchesZeroSeed { get; set; }
        public int? BytesConsumed { get; set; }
        public int? Status { get; set; }
        public int? RequestBytesRead { get; set; }
    }

    [JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonSerializable(typeof(LocalServerConfiguration))]
    [JsonSerializable(typeof(ConfigServerEvent))]
    internal partial class ConfigServerJsonContext : JsonSerializerContext { }
}
