using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace S7Patcher.Source
{
    // Opaque qString/GUID keys and encoded Variant values. No locale conversion,
    // field-name assumptions or claimed identities participate in authorization.
    internal sealed class LocalSessionMetadata : IDisposable
    {
        internal const int MaximumBytes = 65536;
        internal readonly Dictionary<string, byte[]> Attributes = new(StringComparer.Ordinal);
        internal readonly Dictionary<string, Dictionary<string, byte[]>> Members = new(StringComparer.Ordinal);

        internal static bool TryReadLeaveBody(ReadOnlySpan<byte> body,
            out ReadOnlySpan<byte> space, out uint sessionId)
        {
            space = default; sessionId = 0;
            if (body.Length > MaximumBytes) return false;
            Reader reader = new(body);
            return reader.Number(out uint classes) && classes == 0 && reader.Text(out space)
                && reader.Number(out sessionId) && sessionId is > 0 and < uint.MaxValue
                && reader.Byte(out byte flag) && flag <= 1 && reader.Text(out _) && reader.AtEnd;
        }

        internal static bool TryReadBody(ReadOnlySpan<byte> body, bool creation,
            out ReadOnlySpan<byte> space, out uint sessionId, out LocalSessionMetadata result)
        {
            space = default; sessionId = 0; result = null;
            if (body.Length > MaximumBytes) return false;
            Reader reader = new(body);
            LocalSessionMetadata value = new();
            try
            {
                if (!reader.Number(out uint classes) || classes != 0 || !reader.Text(out space)) return false;
                if (!creation && !reader.Number(out sessionId)) return false;
                if (!reader.Map(value.Attributes, false, LocalSessionCreationCodec.MaximumMapEntries)) return false;
                if (creation && (!reader.Text(out _) || !reader.Number(out uint count)
                    || count > LocalSessionCreationCodec.MaximumMembers || !reader.Skip((int)count * 16)
                    || !reader.Number(out _))) return false;
                if (!reader.Number(out uint groups) || groups > LocalSessionCreationCodec.MaximumMapEntries) return false;
                for (uint i = 0; i < groups; ++i)
                {
                    if (!reader.Text(out var name)) return false;
                    Dictionary<string, byte[]> members = new(StringComparer.Ordinal);
                    if (!value.Members.TryAdd(Convert.ToHexString(name), members)) return false;
                    if (!reader.Map(members, true, LocalSessionCreationCodec.MaximumMembers)) return false;
                }
                if (creation && (!reader.Byte(out byte flag) || flag > 1)) return false;
                if (!reader.AtEnd || !value.WithinBounds()) return false;
                result = value;
                return true;
            }
            finally { if (result == null) value.Dispose(); }
        }

        // Copy-on-write: invalid aggregate growth never partially applies an update.
        internal bool TryMerge(LocalSessionMetadata patch, out LocalSessionMetadata merged)
        {
            merged = Clone();
            ReplaceValues(merged.Attributes, patch.Attributes);
            foreach (var group in patch.Members)
            {
                if (!merged.Members.TryGetValue(group.Key, out var target))
                    merged.Members.Add(group.Key, target = new(StringComparer.Ordinal));
                ReplaceValues(target, group.Value);
            }
            if (merged.WithinBounds()) return true;
            merged.Dispose(); merged = null;
            return false;
        }

        internal LocalSessionMetadata Clone()
        {
            LocalSessionMetadata copy = new();
            ReplaceValues(copy.Attributes, Attributes);
            foreach (var group in Members)
            {
                Dictionary<string, byte[]> members = new(StringComparer.Ordinal);
                ReplaceValues(members, group.Value);
                copy.Members.Add(group.Key, members);
            }
            return copy;
        }

        private static void ReplaceValues(Dictionary<string, byte[]> target, Dictionary<string, byte[]> patch)
        {
            foreach (var pair in patch)
            {
                if (target.TryGetValue(pair.Key, out byte[] old)) CryptographicOperations.ZeroMemory(old);
                target[pair.Key] = (byte[])pair.Value.Clone();
            }
        }

        private bool WithinBounds()
        {
            if (Attributes.Count > LocalSessionCreationCodec.MaximumMapEntries
                || Members.Count > LocalSessionCreationCodec.MaximumMapEntries) return false;
            long size = 8;
            foreach (var pair in Attributes) size += 3L + pair.Key.Length / 2 + pair.Value.Length;
            foreach (var group in Members)
            {
                if (group.Value.Count > LocalSessionCreationCodec.MaximumMembers) return false;
                size += 7L + group.Key.Length / 2;
                foreach (var pair in group.Value) size += 16L + pair.Value.Length;
            }
            return size <= MaximumBytes;
        }

        public void Dispose()
        {
            foreach (byte[] value in Attributes.Values) CryptographicOperations.ZeroMemory(value);
            Attributes.Clear();
            foreach (var group in Members.Values)
            {
                foreach (byte[] value in group.Values) CryptographicOperations.ZeroMemory(value);
                group.Clear();
            }
            Members.Clear();
        }

        private ref struct Reader
        {
            private readonly ReadOnlySpan<byte> input;
            private int offset;
            internal Reader(ReadOnlySpan<byte> input) { this.input = input; offset = 0; }
            internal bool AtEnd => offset == input.Length;
            internal bool Skip(int count)
            {
                if (count > input.Length - offset) return false;
                offset += count; return true;
            }
            internal bool Byte(out byte value)
            {
                value = 0;
                if (offset >= input.Length) return false;
                value = input[offset++]; return true;
            }
            internal bool Number(out uint value)
            {
                value = 0;
                if (input.Length - offset < 4) return false;
                value = BinaryPrimitives.ReadUInt32LittleEndian(input[offset..]); offset += 4; return true;
            }
            internal bool Text(out ReadOnlySpan<byte> text)
            {
                text = default;
                if (input.Length - offset < 2) return false;
                int length = BinaryPrimitives.ReadUInt16LittleEndian(input[offset..]); offset += 2;
                if (length == 0) return true;
                if (length > input.Length - offset || input[offset + length - 1] != 0) return false;
                text = input.Slice(offset, length - 1); offset += length; return true;
            }
            internal bool Map(Dictionary<string, byte[]> target, bool guidKeys, uint maximum)
            {
                if (!Number(out uint count) || count > maximum) return false;
                for (uint i = 0; i < count; ++i)
                {
                    ReadOnlySpan<byte> key;
                    if (guidKeys)
                    {
                        int start = offset;
                        if (!Skip(16)) return false;
                        key = input.Slice(start, 16);
                    }
                    else if (!Text(out key)) return false;
                    string encodedKey = Convert.ToHexString(key);
                    if (target.ContainsKey(encodedKey)) return false;
                    int valueStart = offset;
                    if (!Byte(out byte tag)) return false;
                    bool valid = tag switch
                    {
                        0 => true,
                        1 or 2 or 5 or 6 => Skip(8),
                        3 => Skip(1),
                        4 => Text(out _),
                        7 => Skip(16),
                        _ => false
                    };
                    if (!valid) return false;
                    target.Add(encodedKey, input.Slice(valueStart, offset - valueStart).ToArray());
                }
                return true;
            }
        }
    }
}
