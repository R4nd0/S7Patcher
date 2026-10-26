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
        internal const int RetryMilliseconds = 1000;
        internal const int MaximumTransmissions = 4;
        internal const int LifetimeMilliseconds = 120000;
        internal const int KeepAliveMaximumMilliseconds = 1200000;
        internal const int PingReplyIntervalMilliseconds = 100;
        internal const int MaximumPostLoginResponses = 32;
        private readonly PrudpProbePeer peer;
        private readonly ReliableMessageAssembler assembler;
        private readonly LocalLoginRpcEngine rpc;
        private readonly byte[] key;
        private readonly long createdAt;
        private readonly bool keepAlive;
        private readonly LocalSessionRegistry sessions;
        private readonly bool ownsRegistry;
        private long lastPingAt, nextPingReplyAt;
        private readonly Dictionary<ushort, Pending> pending = new();
        private ushort nextOutgoing = 1;
        private int responseCount;
        private int postLoginObservations;
        private int postLoginResponseCount;
        private bool registrationAcknowledged;
        private bool closed;

        internal PrudpLocalLoginSession(PrudpProbePeer peer, IPEndPoint endpoint, string authUrl, long now, bool keepAlive = false,
            LocalSessionRegistry sessions = null)
        {
            if (peer?.ConnectReplySent != true || peer.Connect == null)
                throw new ArgumentException("Established CONNECT context required");
            this.peer = peer;
            rpc = new(peer.SourceVirtualPort, endpoint, authUrl);
            try { key = peer.Connect.DeriveDataKey(); }
            catch { rpc.Dispose(); throw; }
            assembler = new(peer.Connect.InitialClientDataSequence);
            createdAt = now;
            lastPingAt = now;
            this.keepAlive = keepAlive;
            this.sessions = sessions ?? new();
            ownsRegistry = sessions == null;
        }

        internal int PendingCount => pending.Count;
        internal bool Closed => closed;

        internal bool TryReplyToPing(ReadOnlySpan<byte> packet, long now, Action<ConfigServerEvent> emit, out byte[] reply)
        {
            reply = null;
            if (closed || !keepAlive || ExpireIfDue(now, emit) || responseCount != 2 || pending.Count != 0
                || now < nextPingReplyAt || !PrudpPingAckCodec.TryCreateReply(packet, peer, out reply)) return false;
            // Refresh only a fully registered, acknowledged local session after
            // context/checksum validation. An ACK/no-request packet cannot refresh.
            lastPingAt = now;
            nextPingReplyAt = now + PingReplyIntervalMilliseconds;
            return true;
        }

        private bool ExpireIfDue(long now, Action<ConfigServerEvent> emit)
        {
            bool expired = keepAlive
                ? now - createdAt >= KeepAliveMaximumMilliseconds || now - lastPingAt >= LifetimeMilliseconds
                : now - createdAt >= LifetimeMilliseconds;
            if (!expired) return false;
            emit(new() { Event = "local-login-session-expired", Reason = !keepAlive ? "probe-lifetime-ended"
                : now - createdAt >= KeepAliveMaximumMilliseconds ? "keepalive-maximum-ended" : "keepalive-idle-timeout" });
            Dispose(); return true;
        }

        internal PrudpDataCryptoResult ProcessData(ReadOnlySpan<byte> packet, Action<ConfigServerEvent> emit)
        {
            if (closed) return new() { Outcome = "local-login-session-closed" };
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
                emit(new() { Event = "local-login-fragment-observed", Reason = queued.ToString() });
            while (assembler.TryTakeMessage(out byte[] message))
            {
                byte[] response = null;
                try
                {
                    bool search = responseCount == 2;
                    string reason;
                    // Login/Register keep their two-response budget. The opt-in
                    // keepalive service can additionally answer bounded searches
                    // and create requests, sharing the same post-login budget.
                    if (search)
                    {
                        if (postLoginObservations < 8)
                        {
                            postLoginObservations++;
                            emit(new() { Event = "local-post-login-request-observed",
                                Reason = LoginRpcCodec.ClassifyPostLoginRequest(message) });
                        }
                        if (!keepAlive || !registrationAcknowledged || postLoginResponseCount >= MaximumPostLoginResponses || pending.Count >= 2)
                        {
                            emit(new() { Event = "local-login-message-rejected", Reason = "response-budget-exhausted" });
                            continue;
                        }
                        if (!TryReplyToSessionRequest(message, out response, out reason))
                        {
                            emit(new() { Event = "local-login-message-rejected", Reason = reason });
                            continue;
                        }
                    }
                    else if (!rpc.TryHandle(message, out response, out reason))
                    {
                        emit(new() { Event = "local-login-message-rejected", Reason = reason });
                        continue;
                    }
                    if (response.Length > PrudpDataPacketEncoder.PlaintextLimit)
                    {
                        emit(new() { Event = "local-login-message-rejected", Reason = "response-fragment-limit" });
                        Dispose();
                        break;
                    }
                    byte[] encoded = peer.Connect.CreateDataPacket(nextOutgoing, response, key);
                    pending.Add(nextOutgoing, new(encoded));
                    nextOutgoing = unchecked((ushort)(nextOutgoing + 1));
                    if (search) postLoginResponseCount++; else responseCount++;
                    emit(new() { Event = !search ? "local-login-response-queued"
                        : LoginRpcCodec.ClassifyPostLoginRequest(message) == "matchmaking-create-session-v1"
                            ? "local-session-create-response-queued" : "local-session-search-response-queued", Reason = reason,
                        AuthenticationImplemented = false, UdpProtocolImplemented = false });
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(message);
                    if (response != null) CryptographicOperations.ZeroMemory(response);
                }
            }
            if (!closed)
                emit(new() { Event = "local-login-assembly-observed", Reason = assembler.LastDropReason.ToString(),
                    BufferedFragments = assembler.BufferedFragmentCount, AssemblingFragments = assembler.FragmentsInCurrentMessage });
            return result;
        }

        private bool TryReplyToSessionRequest(ReadOnlySpan<byte> message, out byte[] response, out string reason)
        {
            string operation = LoginRpcCodec.ClassifyPostLoginRequest(message);
            if (operation == "matchmaking-create-session-v1")
                return LocalSessionCreationCodec.TryReply(message, sessions, this, out response, out reason);
            if (operation != "matchmaking-search-sessions-v1")
            {
                response = null;
                reason = "unsupported-session-operation";
                return false;
            }
            // Until MatchmakingSession serialization is implemented, never claim
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
                || data.BytesConsumed != packet.Length || data.PayloadLength != 0 || packet[10] != 0)
                return false;
            PrudpDataContext context = PrudpDataAckProbeCodec.GetContext(packet, peer);
            if (!context.KnownPeer || !context.ConnectReplySent || context.RoutingMatches != true
                || context.ClientSessionMatches != true || context.HeaderCookieMatches != true) return false;
            ushort sequence = BinaryPrimitives.ReadUInt16LittleEndian(packet[8..]);
            if (!pending.Remove(sequence, out Pending sent) || sent.Transmissions == 0)
            {
                // An ACK cannot acknowledge a packet which has not been offered
                // for sending. Preserve it if a guessed ACK arrived early.
                if (sent != null) pending.Add(sequence, sent);
                return false;
            }
            CryptographicOperations.ZeroMemory(sent.Packet);
            if (responseCount == 2 && !pending.ContainsKey(1) && !pending.ContainsKey(2)) registrationAcknowledged = true;
            return true;
        }

        // Caller awaits sending each returned packet before any subsequent session
        // operation. Bytes remain session-owned and must not be retained or logged.
        internal IReadOnlyList<byte[]> TakeDue(long now, Action<ConfigServerEvent> emit)
        {
            List<byte[]> due = new();
            if (closed) return due;
            if (ExpireIfDue(now, emit)) return due;
            // Expiry precedes collecting references, so disposal cannot invalidate
            // already collected packets when another outstanding entry expires.
            foreach (Pending sent in pending.Values)
                if (sent.Transmissions >= MaximumTransmissions && now >= sent.NextSend)
                {
                    emit(new() { Event = "local-login-session-expired", Reason = "response-ack-timeout" });
                    Dispose(); return due;
                }
            foreach (Pending sent in pending.Values)
            {
                if (sent.Transmissions != 0 && now < sent.NextSend) continue;
                sent.Transmissions++;
                sent.NextSend = now + RetryMilliseconds;
                due.Add(sent.Packet);
            }
            return due;
        }

        public void Dispose()
        {
            if (closed) return;
            closed = true;
            sessions.RemoveOwner(this);
            if (ownsRegistry) sessions.Dispose();
            foreach (Pending sent in pending.Values) CryptographicOperations.ZeroMemory(sent.Packet);
            pending.Clear(); assembler.Dispose(); rpc.Dispose(); CryptographicOperations.ZeroMemory(key);
        }
        private sealed class Pending
        {
            internal Pending(byte[] packet) => Packet = packet;
            internal byte[] Packet { get; }
            internal int Transmissions { get; set; }
            internal long NextSend { get; set; }
        }
    }
}
