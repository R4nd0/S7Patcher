using System;
using System.Buffers.Binary;

namespace S7Patcher.Source
{
    // Structural probe only. It neither copies nor decodes argument values and
    // returns no token, URL, version, variant value or identity material.
    internal static class LoginRpcArgumentShape
    {
        internal const int MaximumBodyLength = 65536; // Probe cap, not a native protocol maximum.
        internal const int MaximumRegisterUrls = 32;

        internal static bool TryValidate(LoginRpcMethod method, ReadOnlySpan<byte> body,
            out LoginRpcArgumentShapeFailure failure)
        {
            failure = LoginRpcArgumentShapeFailure.None;
            if (method is not (LoginRpcMethod.LoginWithTokenV1 or LoginRpcMethod.RegisterV1))
                return Fail(LoginRpcArgumentShapeFailure.UnknownMethod, out failure);
            if (body.Length > MaximumBodyLength)
                return Fail(LoginRpcArgumentShapeFailure.BodyLimitExceeded, out failure);
            int offset = 0;
            if (!Skip(body, ref offset, 4, out failure)) return false;
            uint mapCount = BinaryPrimitives.ReadUInt32LittleEndian(body);
            if (method == LoginRpcMethod.LoginWithTokenV1)
            {
                // E966E3 inserts this known class/version before serialization.
                // Compare the fixed metadata bytes without creating an input string.
                if (mapCount != 1) return Fail(LoginRpcArgumentShapeFailure.UnsupportedExtensionMap, out failure);
                int classOffset = offset;
                if (!SkipString(body, ref offset, out failure)) return false;
                if (!body.Slice(classOffset + 2, offset - classOffset - 2).SequenceEqual("ClientVersionInfo\0"u8))
                    return Fail(LoginRpcArgumentShapeFailure.UnknownClassVersionName, out failure);
                if (!Skip(body, ref offset, 2, out failure)) return false;
                if (BinaryPrimitives.ReadUInt16LittleEndian(body.Slice(offset - 2, 2)) != 1)
                    return Fail(LoginRpcArgumentShapeFailure.UnsupportedClassVersion, out failure);
                if (!SkipString(body, ref offset, out failure)) return false;
                // E996C0: u16, u16, u16, u32, followed by the EB0230 variant.
                if (!Skip(body, ref offset, 10, out failure)) return false;
                if (!Skip(body, ref offset, 1, out failure)) return false;
                byte tag = body[offset - 1];
                int width;
                switch (tag)
                {
                    case 0: width = 0; break;
                    case 1: case 2: case 5: case 6: width = 8; break;
                    case 3: width = 1; break;
                    case 4:
                        if (!SkipString(body, ref offset, out failure)) return false;
                        width = 0; break;
                    case 7: width = 16; break;
                    default: return Fail(LoginRpcArgumentShapeFailure.UnknownVariantTag, out failure);
                }
                if (!Skip(body, ref offset, width, out failure)
                    || !SkipString(body, ref offset, out failure)) return false;
            }
            else
            {
                if (mapCount != 0) return Fail(LoginRpcArgumentShapeFailure.UnsupportedExtensionMap, out failure);
                if (!Skip(body, ref offset, 4, out failure)) return false;
                uint count = BinaryPrimitives.ReadUInt32LittleEndian(body.Slice(offset - 4, 4));
                if (count is < 1 or > MaximumRegisterUrls)
                    return Fail(LoginRpcArgumentShapeFailure.UrlCountOutOfRange, out failure);
                for (uint index = 0; index < count; index++)
                    if (!SkipString(body, ref offset, out failure)) return false;
            }
            if (offset != body.Length) return Fail(LoginRpcArgumentShapeFailure.TrailingBytes, out failure);
            return true;
        }

        private static bool SkipString(ReadOnlySpan<byte> body, ref int offset,
            out LoginRpcArgumentShapeFailure failure)
        {
            if (!Skip(body, ref offset, 2, out failure)) return false;
            int length = BinaryPrimitives.ReadUInt16LittleEndian(body.Slice(offset - 2, 2));
            // Native null-pointer strings have length0 and no bytes to skip.
            // The known class-name comparison still rejects a null class name.
            if (length == 0) return true;
            if (length > body.Length - offset) return Fail(LoginRpcArgumentShapeFailure.Truncated, out failure);
            if (body[offset + length - 1] != 0)
                return Fail(LoginRpcArgumentShapeFailure.MissingStringTerminator, out failure);
            // Interior bytes are opaque: no ASCII check, NUL scan or string creation.
            offset += length;
            return true;
        }

        private static bool Skip(ReadOnlySpan<byte> body, ref int offset, int length,
            out LoginRpcArgumentShapeFailure failure)
        {
            failure = LoginRpcArgumentShapeFailure.None;
            if (length > body.Length - offset) return Fail(LoginRpcArgumentShapeFailure.Truncated, out failure);
            offset += length;
            return true;
        }

        private static bool Fail(LoginRpcArgumentShapeFailure reason, out LoginRpcArgumentShapeFailure failure)
        { failure = reason; return false; }
    }

    internal enum LoginRpcArgumentShapeFailure
    {
        None, UnknownMethod, BodyLimitExceeded, Truncated, UnsupportedExtensionMap,
        UnknownClassVersionName, UnsupportedClassVersion,
        InvalidStringLength, MissingStringTerminator, UnknownVariantTag, UrlCountOutOfRange, TrailingBytes
    }
}
