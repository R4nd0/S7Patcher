using System;
using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;

namespace S7Patcher.Source
{
    // Isolated stream-3 DATA encoder. No socket, RPC, retry or CLI integration.
    internal static class PrudpDataPacketEncoder
    {
        internal const int PlaintextLimit = 947; // Conservative probe fragment cap, not a protocol maximum.

        internal static byte[] Encode(byte sourceVirtualPort, byte destinationVirtualPort,
            byte serverSession, uint clientCookie, ushort sequence, byte part,
            ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, bool tryCompression = true)
        {
            if (sourceVirtualPort != 0x31) throw new ArgumentOutOfRangeException(nameof(sourceVirtualPort));
            if (destinationVirtualPort >> 4 != 3) throw new ArgumentOutOfRangeException(nameof(destinationVirtualPort));
            if (serverSession == 0) throw new ArgumentOutOfRangeException(nameof(serverSession));
            if (plaintext.Length > PlaintextLimit) throw new ArgumentOutOfRangeException(nameof(plaintext));
            if (key.Length != 16) throw new ArgumentException("AES-128 key required", nameof(key));

            byte[] extended = null, compressed = null, envelope = null, iv = null, ciphertext = null;
            try
            {
                extended = new byte[plaintext.Length + 2];
                plaintext.CopyTo(extended);
                BinaryPrimitives.WriteUInt16LittleEndian(extended.AsSpan(plaintext.Length), sequence);
                int compressedLength = 0;
                if (tryCompression)
                {
                    // Fixed storage comfortably exceeds zlib's worst-case output
                    // for the at-most949-byte input; it cannot grow or retain an old buffer.
                    compressed = new byte[4096];
                    using MemoryStream output = new(compressed, 0, compressed.Length, true, true);
                    output.SetLength(0);
                    using (ZLibStream zlib = new(output, CompressionLevel.Optimal, true)) zlib.Write(extended);
                    compressedLength = checked((int)output.Length);
                }
                bool useCompression = tryCompression && compressedLength < extended.Length;
                envelope = new byte[1 + (useCompression ? compressedLength : extended.Length)];
                if (useCompression)
                {
                    // Native envelope byte is a capacity hint, not the exact size.
                    envelope[0] = (byte)Math.Min(255, extended.Length / compressedLength + 1);
                    compressed.AsSpan(0, compressedLength).CopyTo(envelope.AsSpan(1));
                }
                else extended.CopyTo(envelope, 1); // Zero prefix selects uncompressed bytes.

                iv = RandomNumberGenerator.GetBytes(16);
                using (Aes aes = Aes.Create())
                {
                    aes.SetKey(key);
                    ciphertext = aes.EncryptCbc(envelope, iv, PaddingMode.PKCS7);
                }
                // Fixed10-byte PRUDP header, one part byte, IV/ciphertext, checksum.
                // 0x32 = DATA + reliable + ACK requested; no optional length field.
                byte[] packet = new byte[15 + iv.Length + ciphertext.Length];
                packet[0] = sourceVirtualPort; packet[1] = destinationVirtualPort;
                packet[2] = 0x32; packet[3] = serverSession;
                BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(4), clientCookie);
                BinaryPrimitives.WriteUInt16LittleEndian(packet.AsSpan(8), sequence);
                packet[10] = part;
                iv.CopyTo(packet, 11); ciphertext.CopyTo(packet, 27);
                BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(packet.Length - 4),
                    PrudpHandshakePacketDecoder.ComputeChecksum(packet.AsSpan(0, packet.Length - 4), 0));
                return packet;
            }
            finally
            {
                if (extended != null) CryptographicOperations.ZeroMemory(extended);
                if (compressed != null) CryptographicOperations.ZeroMemory(compressed);
                if (envelope != null) CryptographicOperations.ZeroMemory(envelope);
                if (iv != null) CryptographicOperations.ZeroMemory(iv);
                if (ciphertext != null) CryptographicOperations.ZeroMemory(ciphertext);
            }
        }
    }
}
