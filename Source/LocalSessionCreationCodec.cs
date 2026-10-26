using System;
using System.Buffers.Binary;
using System.Text;

namespace S7Patcher.Source
{
    // Verified CreateSession_V1 wire shape; semantic fields stay opaque until
    // GetSession/member/update handling is implemented. See LOCAL-SESSION-CREATION.
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
            if (body.Length > 65536 || body.Length < 4 || BinaryPrimitives.ReadUInt32LittleEndian(body) != 0) return false;
            int offset = 4;
            if (!ReadString(body, ref offset) || !ReadCount(body, ref offset, MaximumMapEntries, out uint attributes)) return false;
            for (uint i = 0; i < attributes; ++i)
                if (!ReadString(body, ref offset) || !ReadVariant(body, ref offset)) return false;
            if (!ReadString(body, ref offset) || !ReadCount(body, ref offset, MaximumMembers, out uint members)
                || !Skip(body, ref offset, (int)members * 16) || !Skip(body, ref offset, 4)
                || !ReadCount(body, ref offset, MaximumMapEntries, out uint maps)) return false;
            for (uint i = 0; i < maps; ++i)
            {
                if (!ReadString(body, ref offset) || !ReadCount(body, ref offset, MaximumMembers, out uint values)) return false;
                for (uint j = 0; j < values; ++j)
                    if (!Skip(body, ref offset, 16) || !ReadVariant(body, ref offset)) return false;
            }
            return body.Length - offset == 1 && body[offset] <= 1;
        }

        private static bool ReadCount(ReadOnlySpan<byte> body, ref int offset, uint maximum, out uint count)
        {
            count = 0;
            if (body.Length - offset < 4) return false;
            count = BinaryPrimitives.ReadUInt32LittleEndian(body[offset..]); offset += 4;
            return count <= maximum;
        }

        private static bool ReadString(ReadOnlySpan<byte> body, ref int offset)
        {
            if (body.Length - offset < 2) return false;
            int length = BinaryPrimitives.ReadUInt16LittleEndian(body[offset..]); offset += 2;
            if (length == 0) return true;
            if (length > body.Length - offset || body[offset + length - 1] != 0) return false;
            offset += length;
            return true;
        }

        private static bool ReadVariant(ReadOnlySpan<byte> body, ref int offset)
        {
            if (offset >= body.Length) return false;
            byte tag = body[offset++];
            return tag switch
            {
                0 => true,
                1 or 2 or 5 or 6 => Skip(body, ref offset, 8),
                3 => Skip(body, ref offset, 1),
                4 => ReadString(body, ref offset),
                7 => Skip(body, ref offset, 16),
                _ => false
            };
        }

        private static bool Skip(ReadOnlySpan<byte> body, ref int offset, int count)
        {
            if (count > body.Length - offset) return false;
            offset += count;
            return true;
        }

        private static void WriteString(Span<byte> output, ref int offset, string text)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(output[offset..], (ushort)(text.Length + 1)); offset += 2;
            offset += Encoding.ASCII.GetBytes(text.AsSpan(), output[offset..]);
            output[offset++] = 0;
        }
    }
}
