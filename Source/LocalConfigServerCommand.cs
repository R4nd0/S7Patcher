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
                    Message = "Usage: S7Patcher --local-config-server [--http-port 0..65535] [--udp-port 0..65535] [--seconds 1..86400] [--handshake-metadata] [--syn-probe] [--connect-probe] [--data-ack-probe] [--data-crypto-probe] [--local-login-probe] [--local-keepalive-probe]" });
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
                if (name == "--connect-probe")
                {
                    options.ConnectProbe = true;
                    options.SynProbe = true;
                    options.HandshakeMetadata = true;
                    continue;
                }
                if (name == "--data-ack-probe")
                {
                    options.DataAckProbe = true;
                    options.ConnectProbe = true;
                    options.SynProbe = true;
                    options.HandshakeMetadata = true;
                    continue;
                }
                if (name is "--data-crypto-probe" or "--local-login-probe" or "--local-keepalive-probe")
                {
                    if (name is "--local-login-probe" or "--local-keepalive-probe") options.LocalLoginProbe = true;
                    if (name == "--local-keepalive-probe") options.LocalKeepAliveProbe = true;
                    options.DataCryptoProbe = true;
                    options.DataAckProbe = true;
                    options.ConnectProbe = true;
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
        public bool ConnectProbe { get; set; }
        public bool DataAckProbe { get; set; }
        public bool DataCryptoProbe { get; set; }
        public bool LocalLoginProbe { get; set; }
        public bool LocalKeepAliveProbe { get; set; }
    }

    internal static class LocalConfigurationServer
    {
        internal const string ConfigurationPath = "/public/rendezvous/v1/configuration";
        private const int HeaderLimit = 32768;
        private const int FirstLineLimit = 2048;
        private const int ConcurrentRequestLimit = 8;

        internal static async Task RunAsync(LocalConfigServerOptions options, Action<ConfigServerEvent> emit, CancellationToken cancellation)
        {
            if (options.LocalKeepAliveProbe) options.LocalLoginProbe = true;
            bool dataAckProbe = options.DataAckProbe || options.DataCryptoProbe || options.LocalLoginProbe;
            bool connectProbe = options.ConnectProbe || dataAckProbe;
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
            Dictionary<IPEndPoint, PrudpProbePeer> peers = new();
            Dictionary<IPEndPoint, PrudpLocalLoginSession> loginSessions = new();
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
                    Message = options.LocalLoginProbe
                        ? "Experimental local Login/Register responses enabled with run-local identities; no Ubisoft authentication, lobby, matchmaking or playable LAN. Plaintext stays bounded in memory."
                        : options.DataCryptoProbe
                        ? "DATA crypto metadata probe enabled after SYN/CONNECT, with transport ACKs. Plaintext is bounded and discarded; no login, RPC or application response."
                        : dataAckProbe
                        ? "DATA ACK loopback probe enabled after SYN/CONNECT. Transport acknowledgements only; no payload decryption, login or application response."
                        : connectProbe
                        ? "Empty-payload SYN/CONNECT loopback probe enabled. Signed transport key only; no DATA response, login or authentication."
                        : options.SynProbe
                        ? "SYN-only loopback probe enabled; zero checksum seed is a hypothesis. No CONNECT response or authentication."
                        : options.HandshakeMetadata
                        ? "Configuration endpoint only. Passive SYN/CONNECT/DATA metadata enabled; zero checksum seed is a hypothesis, not authentication. No UDP replies."
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
                        Task<UdpReceiveResult> receive = null;
                        while (!stop.IsCancellationRequested)
                        {
                            receive ??= udp.ReceiveAsync(stop.Token).AsTask();
                            if (options.LocalLoginProbe)
                            {
                                // One pending receive only. A bounded timer services
                                // retransmits even when the client sends nothing.
                                await Task.WhenAny(receive, Task.Delay(100, stop.Token));
                                foreach (var entry in loginSessions)
                                    foreach (byte[] outgoing in entry.Value.TakeDue(Environment.TickCount64, emit))
                                    {
                                        await udp.SendAsync(outgoing, entry.Key, stop.Token);
                                        emit(new() { Event = "local-login-data-sent", DatagramLength = outgoing.Length,
                                            AuthenticationImplemented = false, UdpProtocolImplemented = false });
                                    }
                                if (!receive.IsCompleted) continue;
                            }
                            UdpReceiveResult packet = await receive;
                            receive = null;
                            // Default: lengths only. Optional decoding never logs content,
                            // routing fields, crypto material or the remote endpoint.
                            int length = packet.Buffer.Length;
                            Interlocked.Increment(ref datagrams);
                            Interlocked.Add(ref datagramBytes, length);
                            ConfigServerEvent observation = new() { Event = "udp-datagram-observed", DatagramLength = length,
                                DatagramsReceived = Interlocked.Read(ref datagrams), UdpProtocolImplemented = false };
                            if (options.HandshakeMetadata || options.SynProbe || connectProbe)
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
                                else if (PrudpDataPacketDecoder.TryDecode(packet.Buffer, out PrudpDataMetadata data, out _))
                                {
                                    observation.PacketType = "data";
                                    observation.BytesConsumed = data.BytesConsumed;
                                    observation.ChecksumMatchesZeroSeed = PrudpHandshakePacketDecoder.ComputeChecksum(
                                        packet.Buffer.AsSpan(0, data.BytesConsumed - 4), 0) == data.Checksum;
                                    peers.TryGetValue(packet.RemoteEndPoint, out PrudpProbePeer contextPeer);
                                    PrudpDataContext context = PrudpDataAckProbeCodec.GetContext(packet.Buffer, contextPeer);
                                    observation.KnownPeer = context.KnownPeer;
                                    observation.ConnectReplySent = context.ConnectReplySent;
                                    observation.RoutingMatches = context.RoutingMatches;
                                    observation.ClientSessionMatches = context.ClientSessionMatches;
                                    observation.HeaderCookieMatches = context.HeaderCookieMatches;
                                }
                                else if (PrudpControlPacketDecoder.TryDecode(packet.Buffer, out var control, out _))
                                {
                                    observation.PacketType = control.Type == PrudpControlPacketType.Ping ? "ping" : "disconnect";
                                    observation.PacketFlags = control.Flags;
                                    observation.BytesConsumed = control.BytesConsumed;
                                    observation.ChecksumMatchesZeroSeed = PrudpHandshakePacketDecoder.ComputeChecksum(
                                        packet.Buffer.AsSpan(0, control.BytesConsumed - 4), 0) == control.Checksum;
                                    peers.TryGetValue(packet.RemoteEndPoint, out PrudpProbePeer controlPeer);
                                    observation.KnownPeer = controlPeer != null;
                                    observation.ConnectReplySent = controlPeer?.ConnectReplySent ?? false;
                                    observation.RoutingMatches = controlPeer == null ? null : control.SourceVirtualPort == controlPeer.SourceVirtualPort
                                        && control.DestinationVirtualPort == 0x31;
                                    observation.ClientSessionMatches = controlPeer?.Connect?.MatchesClientSession(control.SessionId);
                                    observation.HeaderCookieMatches = controlPeer == null ? null : control.PacketSignature == controlPeer.Cookie;
                                }
                            }
                            emit(observation);
                            if ((options.SynProbe || connectProbe) && IPAddress.IsLoopback(packet.RemoteEndPoint.Address)
                                && PrudpSynProbeCodec.TryReadRequest(packet.Buffer, out PrudpHandshakeMetadata syn))
                            {
                                if (!peers.TryGetValue(packet.RemoteEndPoint, out PrudpProbePeer peer))
                                {
                                    if (peers.Count >= 8) continue;
                                    byte[] random = new byte[4];
                                    uint cookie;
                                    do
                                    {
                                        RandomNumberGenerator.Fill(random);
                                        cookie = BinaryPrimitives.ReadUInt32LittleEndian(random);
                                    } while (cookie == 0);
                                    peer = new() { Cookie = cookie, SourceVirtualPort = syn.SourceVirtualPort };
                                    peers.Add(packet.RemoteEndPoint, peer);
                                }
                                if (connectProbe && peer.SourceVirtualPort != syn.SourceVirtualPort) continue;
                                byte[] reply = PrudpSynProbeCodec.CreateReply(syn, peer.Cookie);
                                await udp.SendAsync(reply, packet.RemoteEndPoint, stop.Token);
                                peer.SynReplySent = true;
                                emit(new() { Event = "syn-probe-reply-sent", DatagramLength = reply.Length,
                                    AuthenticationImplemented = false, UdpProtocolImplemented = false });
                            }
                            else if (connectProbe && IPAddress.IsLoopback(packet.RemoteEndPoint.Address)
                                && packet.Buffer.Length >= 3 && (packet.Buffer[2] & 7) == 1)
                            {
                                if (!peers.TryGetValue(packet.RemoteEndPoint, out PrudpProbePeer peer) || !peer.SynReplySent)
                                {
                                    emit(new() { Event = "connect-probe-request-rejected", Reason = "missing-syn-context" });
                                    continue;
                                }
                                if (!PrudpConnectProbe.TryReadRequest(packet.Buffer, peer.Cookie, peer.SourceVirtualPort,
                                    out PrudpHandshakeMetadata connect, out string rejectionReason))
                                {
                                    emit(new() { Event = "connect-probe-request-rejected", Reason = rejectionReason });
                                    continue;
                                }
                                peer.Connect ??= new PrudpConnectProbe(packet.Buffer, connect, key);
                                if (!peer.Connect.TryGetReply(packet.Buffer, connect, out byte[] reply))
                                {
                                    emit(new() { Event = "connect-probe-request-rejected", Reason = "changed-connect-context" });
                                    continue;
                                }
                                await udp.SendAsync(reply, packet.RemoteEndPoint, stop.Token);
                                peer.ConnectReplySent = true;
                                if (options.LocalLoginProbe && !loginSessions.ContainsKey(packet.RemoteEndPoint))
                                    loginSessions.Add(packet.RemoteEndPoint, new(peer, packet.RemoteEndPoint,
                                        "prudp:/address=127.0.0.1;port=" + udpPort.ToString(CultureInfo.InvariantCulture)
                                        + ";sid=1;stream=3;type=2", Environment.TickCount64, options.LocalKeepAliveProbe));
                                emit(new() { Event = "connect-probe-reply-sent", DatagramLength = reply.Length,
                                    AuthenticationImplemented = false, UdpProtocolImplemented = false });
                            }
                            else if (options.LocalKeepAliveProbe && IPAddress.IsLoopback(packet.RemoteEndPoint.Address)
                                && packet.Buffer.Length >= 3 && (packet.Buffer[2] & 7) == 4)
                            {
                                if (loginSessions.TryGetValue(packet.RemoteEndPoint, out var session)
                                    && session.TryReplyToPing(packet.Buffer, Environment.TickCount64, emit, out byte[] reply))
                                {
                                    await udp.SendAsync(reply, packet.RemoteEndPoint, stop.Token);
                                    emit(new() { Event = "local-ping-ack-sent", DatagramLength = reply.Length,
                                        AuthenticationImplemented = false, UdpProtocolImplemented = false });
                                }
                            }
                            else if (dataAckProbe && IPAddress.IsLoopback(packet.RemoteEndPoint.Address)
                                && packet.Buffer.Length >= 3 && (packet.Buffer[2] & 7) == 2)
                            {
                                peers.TryGetValue(packet.RemoteEndPoint, out PrudpProbePeer peer);
                                loginSessions.TryGetValue(packet.RemoteEndPoint, out PrudpLocalLoginSession loginSession);
                                if (loginSession != null && (packet.Buffer[2] & 0xf8) is 0x08 or 0x48)
                                {
                                    emit(new() { Event = "local-login-ack-observed",
                                        Reason = loginSession.TryAcknowledge(packet.Buffer) ? "response-acknowledged" : "ack-not-matched" });
                                    continue;
                                }
                                if (!PrudpDataAckProbeCodec.TryCreateReply(packet.Buffer, peer, out byte[] reply, out string rejectionReason))
                                {
                                    emit(new() { Event = "data-ack-probe-request-rejected", Reason = rejectionReason });
                                    continue;
                                }
                                await udp.SendAsync(reply, packet.RemoteEndPoint, stop.Token);
                                emit(new() { Event = "data-ack-probe-reply-sent", DatagramLength = reply.Length,
                                    AuthenticationImplemented = false, UdpProtocolImplemented = false });
                                if (options.DataCryptoProbe || options.LocalLoginProbe)
                                {
                                    PrudpDataCryptoResult crypto = loginSession != null
                                        ? loginSession.ProcessData(packet.Buffer, emit)
                                        : PrudpDataCryptoProbe.Inspect(packet.Buffer, peer);
                                    emit(new() { Event = "data-crypto-probe-observed", Reason = crypto.Outcome,
                                        SerializedPayloadLength = crypto.SerializedPayloadLength,
                                        DecryptedEnvelopeLength = crypto.DecryptedEnvelopeLength,
                                        DecodedPayloadLength = crypto.DecodedPayloadLength,
                                        Compressed = crypto.Compressed, SequenceMatches = crypto.SequenceMatches,
                                        AuthenticationImplemented = false, UdpProtocolImplemented = false });
                                }
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
                foreach (PrudpLocalLoginSession session in loginSessions.Values) session.Dispose();
                loginSessions.Clear();
                foreach (PrudpProbePeer peer in peers.Values) peer.Dispose();
                peers.Clear();
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
        public byte? PacketFlags { get; set; }
        public bool? ChecksumMatchesZeroSeed { get; set; }
        public int? BytesConsumed { get; set; }
        public bool? KnownPeer { get; set; }
        public bool? ConnectReplySent { get; set; }
        public bool? RoutingMatches { get; set; }
        public bool? ClientSessionMatches { get; set; }
        public bool? HeaderCookieMatches { get; set; }
        public int? SerializedPayloadLength { get; set; }
        public int? DecryptedEnvelopeLength { get; set; }
        public int? DecodedPayloadLength { get; set; }
        public bool? Compressed { get; set; }
        public bool? SequenceMatches { get; set; }
        public int? BufferedFragments { get; set; }
        public int? AssemblingFragments { get; set; }
        public int? Status { get; set; }
        public int? RequestBytesRead { get; set; }
    }

    [JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonSerializable(typeof(LocalServerConfiguration))]
    [JsonSerializable(typeof(ConfigServerEvent))]
    internal partial class ConfigServerJsonContext : JsonSerializerContext { }
}
