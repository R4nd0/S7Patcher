using System;
using System.Buffers.Binary;
using System.Text;

namespace S7Patcher.Source
{
    // Isolated wire codec. No transport, identities, argument parsing or authentication.
    // The 64KiB whole-message limit is local policy, not a proven native maximum.
    internal static class LoginRpcCodec
    {
        internal const int MaximumMessageLength = 65536;
        private const string Protocol = "LoginProtocol";
        private const string LoginMethod = "LoginProtocol::LoginWithToken_V1";
        private const string RegisterMethod = "LoginProtocol::Register_V1";
        private static readonly byte[] ProtocolBytes = Encoding.ASCII.GetBytes(Protocol);
        private static readonly byte[] LoginMethodBytes = Encoding.ASCII.GetBytes(LoginMethod);
        private static readonly byte[] RegisterMethodBytes = Encoding.ASCII.GetBytes(RegisterMethod);

        internal static bool TryReadRequest(ReadOnlySpan<byte> message, out LoginRpcRequest header, out LoginRpcFailure failure)
        {
            header = default;
            failure = LoginRpcFailure.Truncated;
            if (message.Length < 4) return false;
            if (message.Length > MaximumMessageLength) { failure = LoginRpcFailure.LimitExceeded; return false; }
            if (BinaryPrimitives.ReadUInt32LittleEndian(message) != (uint)(message.Length - 4))
            { failure = LoginRpcFailure.OuterLengthMismatch; return false; }
            int offset = 4;
            if (!ReadString(message, ref offset, out ReadOnlySpan<byte> protocol, out failure)) return false;
            if (!protocol.SequenceEqual(ProtocolBytes)) { failure = LoginRpcFailure.UnknownProtocol; return false; }
            if (message.Length - offset < 5) { failure = LoginRpcFailure.Truncated; return false; }
            if (message[offset++] != 1) { failure = LoginRpcFailure.UnexpectedRequestFlag; return false; }
            uint callId = BinaryPrimitives.ReadUInt32LittleEndian(message[offset..]); offset += 4;
            if (!ReadString(message, ref offset, out ReadOnlySpan<byte> method, out failure)) return false;
            LoginRpcMethod recognized;
            if (method.SequenceEqual(LoginMethodBytes)) recognized = LoginRpcMethod.LoginWithTokenV1;
            else if (method.SequenceEqual(RegisterMethodBytes)) recognized = LoginRpcMethod.RegisterV1;
            else { failure = LoginRpcFailure.UnknownMethod; return false; }
            // The remaining bytes can contain arbitrary argument data. Do not read,
            // copy, decode, validate, or include them in an error or diagnostic string.
            header = new(recognized, callId, offset, message.Length - offset);
            failure = LoginRpcFailure.None;
            return true;
        }

        // Diagnostic classification only: fixed labels, no IDs, arguments or
        // unrecognized wire text leave this method. It never authorizes a reply.
        internal static string ClassifyPostLoginRequest(ReadOnlySpan<byte> message)
        {
            if (message.Length < 4 || message.Length > MaximumMessageLength
                || BinaryPrimitives.ReadUInt32LittleEndian(message) != (uint)(message.Length - 4))
                return "invalid-rpc-envelope";
            int offset = 4;
            if (!ReadString(message, ref offset, out ReadOnlySpan<byte> protocol, out _)
                || message.Length - offset < 5 || message[offset] != 1)
                return "invalid-rpc-envelope";
            offset += 5; // Request flag and opaque call ID; neither is retained.
            if (!ReadString(message, ref offset, out ReadOnlySpan<byte> method, out _))
                return "invalid-rpc-envelope";
            if (protocol.SequenceEqual("MatchmakingProtocol"u8))
            {
                if (method.SequenceEqual("MatchmakingProtocol::SearchSessions_V1"u8)) return "matchmaking-search-sessions-v1";
                if (method.SequenceEqual("MatchmakingProtocol::CreateSession_V1"u8)) return "matchmaking-create-session-v1";
                if (method.SequenceEqual("MatchmakingProtocol::CreateSession2_V1"u8)) return "matchmaking-create-session2-v1";
                return "matchmaking-other-method";
            }
            if (protocol.SequenceEqual(ProtocolBytes))
                return method.SequenceEqual(LoginMethodBytes) ? "login-with-token-v1"
                    : method.SequenceEqual(RegisterMethodBytes) ? "login-register-v1" : "login-other-method";
            return "other-protocol";
        }

        private static bool ReadString(ReadOnlySpan<byte> message, ref int offset,
            out ReadOnlySpan<byte> text, out LoginRpcFailure failure)
        {
            text = default; failure = LoginRpcFailure.Truncated;
            if (message.Length - offset < 2) return false;
            int length = BinaryPrimitives.ReadUInt16LittleEndian(message[offset..]); offset += 2;
            if (length is < 1 or > 255) { failure = LoginRpcFailure.InvalidString; return false; }
            if (length > message.Length - offset) return false;
            ReadOnlySpan<byte> field = message.Slice(offset, length);
            if (field[^1] != 0) { failure = LoginRpcFailure.InvalidString; return false; }
            foreach (byte value in field[..^1])
                if (value is < 0x20 or > 0x7e) { failure = LoginRpcFailure.InvalidString; return false; }
            text = field[..^1]; offset += length;
            failure = LoginRpcFailure.None;
            return true;
        }

        internal static bool TryWriteLoginSuccess(uint callId, in LoginRpcReturn value,
            out byte[] response, out LoginRpcFailure failure)
        {
            response = null;
            if (value.ProfileId.Length != 16) { failure = LoginRpcFailure.InvalidProfileIdLength; return false; }
            if (!StartSuccess(callId, LoginMethod, value.StationUrl, 17, out response, out int offset, out failure)) return false;
            // Preserve the exact sixteen wire bytes. Do not apply System.Guid byte order.
            value.ProfileId.Span.CopyTo(response.AsSpan(offset)); offset += 16;
            WriteString(response, ref offset, value.StationUrl);
            response[offset] = value.Redirect ? (byte)1 : (byte)0;
            return true;
        }

        internal static bool TryWriteRegisterSuccess(uint callId, in RegisterRpcReturn value,
            out byte[] response, out LoginRpcFailure failure)
        {
            if (!StartSuccess(callId, RegisterMethod, value.StationUrl, 4, out response, out int offset, out failure)) return false;
            BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(offset), value.RvConnectionId); offset += 4;
            WriteString(response, ref offset, value.StationUrl);
            return true;
        }

        private static bool StartSuccess(uint callId, string method, string stationUrl, int fixedReturnLength,
            out byte[] response, out int offset, out LoginRpcFailure failure)
        {
            response = null; offset = 0; failure = LoginRpcFailure.InvalidString;
            // Deliberately narrower than native DDL: nonnull printable ASCII only.
            // Empty is structurally valid; no StationURL semantic validity is asserted.
            if (stationUrl == null) return false;
            if (stationUrl.Length > 65534) { failure = LoginRpcFailure.LimitExceeded; return false; }
            foreach (char value in stationUrl) if (value is < ' ' or > '~') return false;
            string responseMethod = method + "*"; // A literal suffix, never a wildcard.
            int length = 4 + Protocol.Length + 3 + 1 + 1 + 4 + responseMethod.Length + 3
                + fixedReturnLength + stationUrl.Length + 3;
            if (length > MaximumMessageLength) { failure = LoginRpcFailure.LimitExceeded; return false; }
            response = new byte[length];
            BinaryPrimitives.WriteUInt32LittleEndian(response, (uint)(length - 4)); offset = 4;
            WriteString(response, ref offset, Protocol);
            response[offset++] = 0; // Response.
            response[offset++] = 1; // Generic success discriminator, not redirect.
            BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(offset), callId); offset += 4;
            WriteString(response, ref offset, responseMethod);
            failure = LoginRpcFailure.None;
            return true;
        }

        private static void WriteString(Span<byte> output, ref int offset, string text)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(output[offset..], (ushort)(text.Length + 1)); offset += 2;
            offset += Encoding.ASCII.GetBytes(text.AsSpan(), output[offset..]);
            output[offset++] = 0;
        }
    }

    internal enum LoginRpcMethod { Unknown, LoginWithTokenV1, RegisterV1 }
    internal enum LoginRpcFailure
    {
        None, Truncated, LimitExceeded, OuterLengthMismatch, InvalidString,
        UnknownProtocol, UnexpectedRequestFlag, UnknownMethod, InvalidProfileIdLength
    }

    // Ordinary structs intentionally avoid generated ToString methods containing IDs.
    internal readonly struct LoginRpcRequest
    {
        internal LoginRpcRequest(LoginRpcMethod method, uint callId, int bodyOffset, int bodyLength)
        { Method = method; CallId = callId; BodyOffset = bodyOffset; BodyLength = bodyLength; }
        internal LoginRpcMethod Method { get; }
        internal uint CallId { get; }
        internal int BodyOffset { get; }
        internal int BodyLength { get; }
    }
    internal readonly struct LoginRpcReturn
    {
        internal LoginRpcReturn(ReadOnlyMemory<byte> profileId, string stationUrl, bool redirect)
        { ProfileId = profileId; StationUrl = stationUrl; Redirect = redirect; }
        internal ReadOnlyMemory<byte> ProfileId { get; }
        internal string StationUrl { get; }
        internal bool Redirect { get; }
    }
    internal readonly struct RegisterRpcReturn
    {
        internal RegisterRpcReturn(uint rvConnectionId, string stationUrl)
        { RvConnectionId = rvConnectionId; StationUrl = stationUrl; }
        internal uint RvConnectionId { get; }
        internal string StationUrl { get; }
    }
}
