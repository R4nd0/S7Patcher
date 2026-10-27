using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;

namespace S7Patcher.Source
{
    // Single-threaded bounded experiment, not a complete PRUDP endpoint. Every
    // plaintext message is consumed in memory, then zeroed. Valid create bodies
    // live in the bounded registry until owner teardown. Timers are probe policy.
    internal sealed class PrudpLocalLoginSession : IDisposable
    {
        internal const int RetryMilliseconds = ReliableResponseQueue.RetryMilliseconds;
        internal const int MaximumTransmissions = ReliableResponseQueue.MaximumTransmissions;
        internal const int LifetimeMilliseconds = 120000;
#if S7_LOCAL_PAIR_LAB
        internal const int KeepAliveIdleMilliseconds = 900000;
        internal const int KeepAliveMaximumMilliseconds = 3600000;
        internal const int MaximumPostLoginResponses = 512;
#else
        internal const int KeepAliveIdleMilliseconds = LifetimeMilliseconds;
        internal const int KeepAliveMaximumMilliseconds = 1200000;
        internal const int MaximumPostLoginResponses = 32;
#endif
        internal const int PingReplyIntervalMilliseconds = 100;
        internal const int LanIdleMilliseconds = 900000;
        internal const int LanMaximumMilliseconds = 86400000;
        internal const int LanResponseWindowMilliseconds = 60000;
        internal const int LanResponsesPerWindow = 512;
        private readonly PrudpProbePeer peer;
        private readonly ReliableMessageAssembler assembler;
        private readonly LocalLoginRpcEngine rpc;
        private readonly byte[] key;
        private readonly long createdAt;
        private readonly bool keepAlive;
        private readonly bool lanKeepAlive;
        private readonly int idleMilliseconds, maximumMilliseconds;
        private readonly LocalSessionRegistry sessions;
        private readonly bool ownsRegistry;
        private long lastActivityAt, nextPingReplyAt;
        private readonly ReliableResponseQueue pending = new();
        private int responseCount;
        private readonly HashSet<string> observedOperations = new(StringComparer.Ordinal);
        private int postLoginResponseCount;
        private long responseWindowAt;
        private bool registrationAcknowledged;
        private bool joinFailureObserved;
        private bool closed;

        internal PrudpLocalLoginSession(PrudpProbePeer peer, IPEndPoint endpoint, string authUrl, long now, bool keepAlive = false,
            LocalSessionRegistry sessions = null, LocalNetworkPolicy network = null)
        {
            if (peer?.ConnectReplySent != true || peer.Connect == null)
                throw new ArgumentException("Established CONNECT context required");
            this.peer = peer;
            rpc = new(peer.SourceVirtualPort, endpoint, authUrl, network);
            try { key = peer.Connect.DeriveDataKey(); }
            catch { rpc.Dispose(); throw; }
            assembler = new(peer.Connect.InitialClientDataSequence);
            createdAt = now;
            lastActivityAt = now;
            this.keepAlive = keepAlive;
            lanKeepAlive = keepAlive && network?.IsLan == true;
            idleMilliseconds = lanKeepAlive ? LanIdleMilliseconds : KeepAliveIdleMilliseconds;
            maximumMilliseconds = lanKeepAlive ? LanMaximumMilliseconds : KeepAliveMaximumMilliseconds;
            responseWindowAt = now;
            this.sessions = sessions ?? new();
            ownsRegistry = sessions == null;
        }

        internal int PendingCount => pending.Count;
        internal bool Closed => closed;

        private void Emit(Action<ConfigServerEvent> sink, ConfigServerEvent record)
        {
            record.SourceRole = rpc.ObservedTransportRole;
            sink(record);
        }

        internal bool TryReplyToPing(ReadOnlySpan<byte> packet, long now, Action<ConfigServerEvent> emit, out byte[] reply)
        {
            reply = null;
            if (closed || !keepAlive || ExpireIfDue(now, emit) || responseCount != 2 || pending.Count != 0
                || now < nextPingReplyAt || !PrudpPingAckCodec.TryCreateReply(packet, peer, out reply)) return false;
            // Refresh only a fully registered, acknowledged local session after
            // context/checksum validation. An ACK/no-request packet cannot refresh.
            lastActivityAt = Math.Max(lastActivityAt, now);
            nextPingReplyAt = now + PingReplyIntervalMilliseconds;
            return true;
        }

        private bool ExpireIfDue(long now, Action<ConfigServerEvent> emit)
        {
            bool expired = keepAlive
                ? now - createdAt >= maximumMilliseconds || now - lastActivityAt >= idleMilliseconds
                : now - createdAt >= LifetimeMilliseconds;
            if (!expired) return false;
            Emit(emit, new() { Event = "local-login-session-expired", Reason = !keepAlive ? "probe-lifetime-ended"
                : now - createdAt >= maximumMilliseconds ? "keepalive-maximum-ended" : "keepalive-idle-timeout" });
            Dispose(); return true;
        }

        // Production passes its monotonic receive time. Clock-free codec fixtures
        // can omit it; they then exercise no activity extension.
        internal PrudpDataCryptoResult ProcessData(ReadOnlySpan<byte> packet, Action<ConfigServerEvent> emit, long? now = null)
        {
            if (closed || (now.HasValue && ExpireIfDue(now.Value, emit)))
                return new() { Outcome = "local-login-session-closed" };
            if (!PrudpDataAckProbeCodec.TryReadRequest(packet, peer, out _, out _)
                || (packet[2] & 0xf8) is not (0x30 or 0x70))
                return new() { Outcome = "local-login-requires-reliable-data" };
            ushort sequence = BinaryPrimitives.ReadUInt16LittleEndian(packet[8..]);
            byte part = packet[10];
            ReliableEnqueueResult queued = ReliableEnqueueResult.Accepted;
            PrudpDataCryptoResult result = PrudpDataCryptoProbe.Inspect(packet, peer,
                plaintext => queued = assembler.AddFragment(sequence, part, plaintext));
            if (result.SequenceMatches != true) return result;
            if (queued != ReliableEnqueueResult.Accepted)
                Emit(emit, new() { Event = "local-login-fragment-observed", Reason = queued.ToString() });
            while (assembler.TryTakeMessage(out byte[] message))
            {
                byte[] response = null;
                try
                {
                    bool search = responseCount == 2;
                    string reason;
                    // Login/Register keep their two-response budget. The opt-in
                    // keepalive service can additionally answer bounded searches
                    // and create/update/leave requests, sharing the same post-login budget.
                    if (search)
                    {
                        // Only an explicitly configured two-address LAN uses
                        // renewable fixed-window budgets. Pending ciphertext,
                        // retries, peer allowlisting and idle expiry stay bounded.
                        if (lanKeepAlive && now.HasValue && now.Value - responseWindowAt >= LanResponseWindowMilliseconds)
                        { responseWindowAt = now.Value; postLoginResponseCount = 0; }
                        if (observedOperations.Count < 8)
                        {
                            string operation = LoginRpcCodec.ClassifyPostLoginRequest(message);
                            if (observedOperations.Add(operation))
                                Emit(emit, new() { Event = "local-post-login-request-observed", Reason = operation });
                        }
                        int responseLimit = lanKeepAlive ? LanResponsesPerWindow : MaximumPostLoginResponses;
                        if (!keepAlive || !registrationAcknowledged || postLoginResponseCount >= responseLimit || pending.Count >= ReliableResponseQueue.MaximumResponses)
                        {
                            Emit(emit, new() { Event = "local-login-message-rejected", Reason = "response-budget-exhausted" });
                            continue;
                        }
                        if (LoginRpcCodec.ClassifyPostLoginRequest(message) == "matchmaking-report-join-failure-v1")
                        {
                            // One redacted observation per registered transport. No
                            // success response, membership transition or text logging.
                            if (!joinFailureObserved)
                            {
                                joinFailureObserved = true;
                                bool valid = sessions.TryObserveJoinFailure(this, rpc, message, out uint sessionKind, out int length, out reason, out var category);
                                Emit(emit, new() { Event = "local-session-join-failure-observed", Reason = reason,
                                    ReportedSessionKind = valid ? sessionKind : null, ReportTextLength = valid ? length : null,
                                    ReportedFailureCategory = valid ? category : null });
                            }
                            continue;
                        }
                        if (!TryReplyToSessionRequest(message, out response, out reason))
                        {
                            Emit(emit, new() { Event = "local-login-message-rejected", Reason = reason });
                            continue;
                        }
                    }
                    else if (!rpc.TryHandle(message, out response, out reason))
                    {
                        Emit(emit, new() { Event = "local-login-message-rejected", Reason = reason });
                        continue;
                    }
                    if (!pending.TryEnqueue(response,
                        (sequence, part, bytes) => peer.Connect.CreateDataPacket(sequence, bytes, key, part)))
                    {
                        Emit(emit, new() { Event = "local-login-message-rejected", Reason = "response-fragment-limit" });
                        Dispose();
                        break;
                    }
                    if (search) postLoginResponseCount++; else responseCount++;
                    // Only a fully reassembled, validated and answered RPC from
                    // an acknowledged registration is activity. Malformed DATA,
                    // duplicates, ACKs and rejected/budget-exhausted calls are not.
                    if (keepAlive && registrationAcknowledged && now.HasValue)
                        lastActivityAt = Math.Max(lastActivityAt, now.Value);
                    Emit(emit, new() { Event = !search ? "local-login-response-queued"
                        : LoginRpcCodec.ClassifyPostLoginRequest(message) == "matchmaking-create-session-v1"
                            ? "local-session-create-response-queued"
                            : LoginRpcCodec.ClassifyPostLoginRequest(message) == "matchmaking-update-session-v1"
                                ? "local-session-update-response-queued"
                                : LoginRpcCodec.ClassifyPostLoginRequest(message) == "matchmaking-leave-session-v1"
                                    ? "local-session-leave-response-queued"
                                    : LoginRpcCodec.ClassifyPostLoginRequest(message) == "matchmaking-get-session-v1"
                                        ? "local-session-get-response-queued"
                                        : LoginRpcCodec.ClassifyPostLoginRequest(message) == "matchmaking-join-session-v1"
                                            ? "local-session-join-response-queued"
                                            : LoginRpcCodec.ClassifyPostLoginRequest(message) == "matchmaking-report-join-success-v1"
                                                ? "local-session-join-success-response-queued" : "local-session-search-response-queued", Reason = reason,
                        AuthenticationImplemented = false, UdpProtocolImplemented = false });
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(message);
                    if (response != null) CryptographicOperations.ZeroMemory(response);
                }
            }
            if (!closed)
                Emit(emit, new() { Event = "local-login-assembly-observed", Reason = assembler.LastDropReason.ToString(),
                    BufferedFragments = assembler.BufferedFragmentCount, AssemblingFragments = assembler.FragmentsInCurrentMessage });
            return result;
        }

        private bool TryReplyToSessionRequest(ReadOnlySpan<byte> message, out byte[] response, out string reason)
        {
            string operation = LoginRpcCodec.ClassifyPostLoginRequest(message);
            if (operation == "matchmaking-create-session-v1")
                return LocalSessionCreationCodec.TryReply(message, sessions, this, rpc, out response, out reason);
            if (operation == "matchmaking-update-session-v1")
                return LocalSessionUpdateCodec.TryReply(message, sessions, this, out response, out reason);
            if (operation == "matchmaking-leave-session-v1")
                return LocalSessionLeaveCodec.TryReply(message, sessions, this, out response, out reason);
            if (sessions.CatalogueProbe && operation == "matchmaking-get-session-v1")
                return LocalSessionCatalogueCodec.TryGet(message, sessions, this, out response, out reason);
            if (sessions.CatalogueProbe && operation == "matchmaking-join-session-v1")
                return LocalSessionJoinCodec.TryReply(message, sessions, this, rpc, out response, out reason);
            if (sessions.CatalogueProbe && operation == "matchmaking-report-join-success-v1")
                return LocalSessionJoinSuccessCodec.TryReply(message, sessions, this, rpc, out response, out reason);
            if (operation != "matchmaking-search-sessions-v1")
            {
                response = null;
                reason = "unsupported-session-operation";
                return false;
            }
            if (sessions.CatalogueProbe)
                return LocalSessionCatalogueCodec.TrySearch(message, sessions, this, out response, out reason);
            if (sessions.DisplayProbe)
                return LocalSessionDisplayCodec.TryReply(message, sessions, this, out response, out reason);
            // Until a live catalogue is implemented, never claim
            // an empty catalogue after any local peer has actually created one.
            if (sessions.Count != 0)
            {
                response = null;
                reason = "nonempty-session-catalogue-not-yet-supported";
                return false;
            }
            return LocalSessionSearchCodec.TryReply(message, out response, out reason);
        }

        internal bool TryAcknowledge(ReadOnlySpan<byte> packet)
        {
            if (closed || packet.Length < 15 || (packet[2] & 0xf8) is not (0x08 or 0x48)
                || !PrudpDataPacketDecoder.TryDecode(packet, out var data, out _, 0)
                || data.BytesConsumed != packet.Length || data.PayloadLength != 0)
                return false;
            PrudpDataContext context = PrudpDataAckProbeCodec.GetContext(packet, peer);
            if (!context.KnownPeer || !context.ConnectReplySent || context.RoutingMatches != true
                || context.ClientSessionMatches != true || context.HeaderCookieMatches != true) return false;
            ushort sequence = BinaryPrimitives.ReadUInt16LittleEndian(packet[8..]);
            if (!pending.TryAcknowledge(sequence, packet[10])) return false;
            if (responseCount == 2 && pending.CompletedResponses >= 2) registrationAcknowledged = true;
            return true;
        }

        // Caller awaits sending each returned packet before any subsequent session
        // operation. Bytes remain session-owned and must not be retained or logged.
        internal IReadOnlyList<byte[]> TakeDue(long now, Action<ConfigServerEvent> emit)
        {
            List<byte[]> due = new();
            if (closed) return due;
            if (ExpireIfDue(now, emit)) return due;
            var packets = pending.TakeDue(now, out bool timedOut);
            if (timedOut)
            {
                Emit(emit, new() { Event = "local-login-session-expired", Reason = "response-ack-timeout" });
                Dispose();
            }
            return packets;
        }

        public void Dispose()
        {
            if (closed) return;
            closed = true;
            observedOperations.Clear();
            sessions.RemoveOwner(this);
            if (ownsRegistry) sessions.Dispose();
            pending.Dispose(); assembler.Dispose(); rpc.Dispose(); CryptographicOperations.ZeroMemory(key);
        }
    }
}
