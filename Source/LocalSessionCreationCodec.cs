using System;
using System.Buffers.Binary;
using System.Text;

namespace S7Patcher.Source
{
    // Verified CreateSession_V1 wire shape; semantic fields stay opaque until
    // GetSession/member handling is implemented. See LOCAL-SESSION-CREATION.
    internal static class LocalSessionCreationCodec
    {
        private const string Protocol = "MatchmakingProtocol";
        private const string Method = "MatchmakingProtocol::CreateSession_V1";
        internal const int MaximumMapEntries = 64;
        internal const int MaximumMembers = 256;

        internal static bool TryReply(ReadOnlySpan<byte> message, LocalSessionRegistry registry,
            object owner, out byte[] response, out string reason)
        {
            response = null;
            reason = "unsupported-create-header";
            if (LoginRpcCodec.ClassifyPostLoginRequest(message) != "matchmaking-create-session-v1") return false;
            int callOffset = 4 + Protocol.Length + 3 + 1;
            int bodyOffset = callOffset + 4 + Method.Length + 3;
            if (!registry.TryCreate(owner, message[bodyOffset..], out uint sessionId, out reason)) return false;
            uint callId = BinaryPrimitives.ReadUInt32LittleEndian(message[callOffset..]);
            string responseMethod = Method + "*";
            response = new byte[4 + Protocol.Length + 3 + 2 + 4 + responseMethod.Length + 3 + 4];
            BinaryPrimitives.WriteUInt32LittleEndian(response, (uint)(response.Length - 4));
            int offset = 4;
            WriteString(response, ref offset, Protocol);
            response[offset++] = 0;
            response[offset++] = 1;
            BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(offset), callId); offset += 4;
            WriteString(response, ref offset, responseMethod);
            BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(offset), sessionId);
            return true;
        }

        internal static bool ValidBody(ReadOnlySpan<byte> body)
        {
            bool valid = LocalSessionMetadata.TryReadBody(body, true, out _, out _, out var metadata);
            metadata?.Dispose();
            return valid;
        }

        private static void WriteString(Span<byte> output, ref int offset, string text)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(output[offset..], (ushort)(text.Length + 1)); offset += 2;
            offset += Encoding.ASCII.GetBytes(text.AsSpan(), output[offset..]);
            output[offset++] = 0;
        }
    }
}
