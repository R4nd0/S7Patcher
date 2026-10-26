using System;
using System.Buffers.Binary;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace S7Patcher.Source
{
    // Empty local catalogue only. No hosting/joining, external lookup or argument
    // persistence. Layout anchors are documented in docs/LOCAL-SESSION-SEARCH.md.
    internal static class LocalSessionSearchCodec
    {
        private const string Protocol = "MatchmakingProtocol";
        private const string Method = "MatchmakingProtocol::SearchSessions_V1";
        internal const int MaximumFilters = 64;

        internal static bool TryReply(ReadOnlySpan<byte> message, out byte[] response, out string reason)
        {
            response = null;
            reason = "unsupported-search-header";
            if (LoginRpcCodec.ClassifyPostLoginRequest(message) != "matchmaking-search-sessions-v1") return false;
            int callOffset = 4 + Protocol.Length + 3 + 1;
            int bodyOffset = callOffset + 4 + Method.Length + 3;
            reason = "unsupported-search-arguments";
            if (!TryReadBody(message[bodyOffset..], out var query)) return false;
            query.Dispose();
            uint callId = BinaryPrimitives.ReadUInt32LittleEndian(message[callOffset..]);
            string responseMethod = Method + "*";
            response = new byte[4 + Protocol.Length + 3 + 2 + 4 + responseMethod.Length + 3 + 8];
            BinaryPrimitives.WriteUInt32LittleEndian(response, (uint)(response.Length - 4));
            int offset = 4;
            WriteString(response, ref offset, Protocol);
            response[offset++] = 0; // Response.
            response[offset++] = 1; // Generic success discriminator.
            BinaryPrimitives.WriteUInt32LittleEndian(response.AsSpan(offset), callId); offset += 4;
            WriteString(response, ref offset, responseMethod);
            // The remaining eight zero bytes are u32 session count, u32 map count.
            reason = "local-empty-session-search-response-created";
            return true;
        }

        internal sealed class Query : IDisposable
        {
            internal byte[] Space = [], Selector = [];
            internal uint Limit;
            internal readonly Dictionary<string, byte[]> Filters = new(StringComparer.Ordinal);
            public void Dispose()
            {
                CryptographicOperations.ZeroMemory(Space); CryptographicOperations.ZeroMemory(Selector);
                foreach (var value in Filters.Values) CryptographicOperations.ZeroMemory(value);
                Filters.Clear(); Limit = 0;
            }
        }

        internal static bool TryReadQuery(ReadOnlySpan<byte> message, out Query query)
        {
            query = null;
            return LoginRpcCodec.ClassifyPostLoginRequest(message) == "matchmaking-search-sessions-v1"
                && TryReadBody(message[(4 + Protocol.Length + 3 + 1 + 4 + Method.Length + 3)..], out query);
        }

        private static bool TryReadBody(ReadOnlySpan<byte> body, out Query query)
        {
            query = null;
            Query parsed = new();
            try
            {
                if (!ReadBody(body, parsed)) return false;
                query = parsed; return true;
            }
            finally { if (query == null) parsed.Dispose(); }
        }

        private static bool ReadBody(ReadOnlySpan<byte> body, Query query)
        {
            if (body.Length < 4 || BinaryPrimitives.ReadUInt32LittleEndian(body) != 2) return false;
            int offset = 4, classes = 0;
            for (int i = 0; i < 2; ++i)
            {
                if (!ReadString(body, ref offset, out var name) || body.Length - offset < 2
                    || BinaryPrimitives.ReadUInt16LittleEndian(body[offset..]) != 1) return false;
                offset += 2;
                int flag = name.SequenceEqual("MatchmakingSession"u8) ? 1
                    : name.SequenceEqual("MatchmakingSessionMember"u8) ? 2 : 0;
                if (flag == 0 || (classes & flag) != 0) return false;
                classes |= flag;
            }
            // Native helper uses default_session_<space> and default_query.
            // Retain exact bytes; this parser does not invent filter semantics.
            if (!ReadString(body, ref offset, out var space) || !ReadString(body, ref offset, out var selector)
                || body.Length - offset < 4) return false;
            query.Space = space.ToArray(); query.Selector = selector.ToArray();
            uint count = BinaryPrimitives.ReadUInt32LittleEndian(body[offset..]); offset += 4;
            if (count > MaximumFilters) return false;
            for (uint i = 0; i < count; ++i)
            {
                if (!ReadString(body, ref offset, out var key) || offset >= body.Length) return false;
                string encodedKey = Convert.ToHexString(key);
                if (query.Filters.ContainsKey(encodedKey)) return false;
                int start = offset;
                byte tag = body[offset++];
                int width;
                switch (tag)
                {
                    case 0: width = 0; break;
                    case 1: case 2: case 5: case 6: width = 8; break;
                    case 3: width = 1; break;
                    case 4:
                        if (!ReadString(body, ref offset, out _)) return false;
                        width = 0; break;
                    case 7: width = 16; break;
                    default: return false;
                }
                if (width > body.Length - offset) return false;
                offset += width;
                query.Filters.Add(encodedKey, body[start..offset].ToArray());
            }
            if (body.Length - offset != 4) return false;
            query.Limit = BinaryPrimitives.ReadUInt32LittleEndian(body[offset..]);
            return true;
        }

        private static bool ReadString(ReadOnlySpan<byte> body, ref int offset, out ReadOnlySpan<byte> text)
        {
            text = default;
            if (body.Length - offset < 2) return false;
            int length = BinaryPrimitives.ReadUInt16LittleEndian(body[offset..]); offset += 2;
            if (length == 0) return true; // Native null qString representation.
            if (length > body.Length - offset || body[offset + length - 1] != 0) return false;
            text = body.Slice(offset, length - 1); offset += length;
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
