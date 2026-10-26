using System;
using System.Buffers.Binary;
using System.Text;

namespace S7Patcher.Source
{
    internal static class LocalSessionUpdateCodec
    {
        private const string Protocol = "MatchmakingProtocol";
        private const string Method = "MatchmakingProtocol::UpdateSession_V1";

        internal static bool TryReply(ReadOnlySpan<byte> message, LocalSessionRegistry registry,
            object owner, out byte[] response, out string reason)
        {
            response = null; reason = "unsupported-update-header";
            if (LoginRpcCodec.ClassifyPostLoginRequest(message) != "matchmaking-update-session-v1") return false;
            int callOffset = 4 + Protocol.Length + 3 + 1;
            int bodyOffset = callOffset + 4 + Method.Length + 3;
            if (!registry.TryUpdate(owner, message[bodyOffset..], out reason)) return false;
            // The original dispatcher consumes no return fields for UpdateSession.
            string responseMethod = Method + "*";
            response = new byte[4 + Protocol.Length + 3 + 2 + 4 + responseMethod.Length + 3];
            BinaryPrimitives.WriteUInt32LittleEndian(response, (uint)(response.Length - 4));
            int offset = 4;
            WriteString(response, ref offset, Protocol);
            response[offset++] = 0; response[offset++] = 1;
            message.Slice(callOffset, 4).CopyTo(response.AsSpan(offset)); offset += 4;
            WriteString(response, ref offset, responseMethod);
            return true;
        }

        private static void WriteString(Span<byte> output, ref int offset, string value)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(output[offset..], (ushort)(value.Length + 1)); offset += 2;
            offset += Encoding.ASCII.GetBytes(value.AsSpan(), output[offset..]);
            output[offset++] = 0;
        }
    }
}
