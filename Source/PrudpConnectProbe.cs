using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace S7Patcher.Source
{
    // Empty-payload CONNECT experiment only. A signed agreement key is not a login.
    internal sealed class PrudpConnectProbe : IDisposable
    {
        private readonly ECDiffieHellman agreementKey;
        private readonly byte[] clientKey;
        private readonly byte clientSession;
        private readonly ushort sequence;
        private readonly uint clientCookie;
        private readonly byte[] reply;

        internal static bool TryReadRequest(ReadOnlySpan<byte> packet, uint serverCookie, byte sourceVirtualPort,
            out PrudpHandshakeMetadata request, out string rejectionReason)
        {
            rejectionReason = "invalid-structure-or-checksum";
            if (!PrudpHandshakePacketDecoder.TryDecode(packet, out request, out _, 0)) return false;
            if (request.Type != PrudpHandshakePacketType.Connect || request.Flags is not (0xb0 or 0xf0))
                return Reject("unsupported-connect-flags", out request, out rejectionReason);
            if (request.SourceVirtualPort != sourceVirtualPort || sourceVirtualPort >> 4 != 3 || request.DestinationVirtualPort != 0x31)
                return Reject("different-routing-context", out request, out rejectionReason);
            if (request.SessionId == 0) return Reject("zero-client-session", out request, out rejectionReason);
            if (request.PacketSignature != serverCookie) return Reject("syn-cookie-mismatch", out request, out rejectionReason);
            if (request.PayloadLength != 0) return Reject("nonempty-payload", out request, out rejectionReason);
            if (request.BytesConsumed != packet.Length) return Reject("trailing-frame", out request, out rejectionReason);
            if (request.PublicKeyLength != 72) return Reject("unsupported-key-blob", out request, out rejectionReason);
            ReadOnlySpan<byte> blob = packet.Slice(request.PublicKeyOffset, request.PublicKeyLength);
            if (BinaryPrimitives.ReadUInt32LittleEndian(blob) != 0x314b4345
                || BinaryPrimitives.ReadUInt32LittleEndian(blob[4..]) != 32)
                return Reject("unsupported-key-blob", out request, out rejectionReason);
            try
            {
                // Let the crypto provider validate this public point, not just its byte count.
                using ECDiffieHellman peer = ECDiffieHellman.Create(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint { X = blob.Slice(8, 32).ToArray(), Y = blob.Slice(40, 32).ToArray() }
                });
            }
            catch (CryptographicException) { return Reject("invalid-public-point", out request, out rejectionReason); }
            catch (ArgumentException) { return Reject("invalid-public-point", out request, out rejectionReason); }
            // Windows CNG can wrap invalid point parameters in this exception.
            catch (PlatformNotSupportedException) { return Reject("invalid-public-point", out request, out rejectionReason); }
            rejectionReason = null;
            return true;
        }

        internal PrudpConnectProbe(ReadOnlySpan<byte> packet, in PrudpHandshakeMetadata request, ECDsa signingKey)
        {
            clientKey = packet.Slice(request.PublicKeyOffset, request.PublicKeyLength).ToArray();
            clientSession = request.SessionId;
            sequence = request.SequenceId;
            clientCookie = request.ConnectionSignature;
            agreementKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            try
            {
                ECParameters parameters = agreementKey.ExportParameters(false);
                byte[] blob = new byte[72];
                BinaryPrimitives.WriteUInt32LittleEndian(blob, 0x314b4345); // ECK1, separate from the ECS1 signing key.
                BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(4), 32);
                if (parameters.Q.X?.Length != 32 || parameters.Q.Y?.Length != 32)
                    throw new CryptographicException("Unexpected P-256 agreement point size");
                parameters.Q.X.CopyTo(blob, 8);
                parameters.Q.Y.CopyTo(blob, 40);
                byte[] signature = signingKey.SignData(blob, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                if (signature.Length != 64) throw new CryptographicException("Unexpected P-256 signature size");
                reply = new byte[158];
                reply[0] = request.DestinationVirtualPort;
                reply[1] = request.SourceVirtualPort;
                reply[2] = 0x89;
                reply[3] = (byte)RandomNumberGenerator.GetInt32(1, 256);
                BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(4), clientCookie);
                BinaryPrimitives.WriteUInt16LittleEndian(reply.AsSpan(8), sequence);
                // Connection signature at 10 is zero for ACK; no new cookie.
                BinaryPrimitives.WriteUInt16LittleEndian(reply.AsSpan(14), 64);
                signature.CopyTo(reply, 16);
                BinaryPrimitives.WriteUInt16LittleEndian(reply.AsSpan(80), 72);
                blob.CopyTo(reply, 82);
                BinaryPrimitives.WriteUInt32LittleEndian(reply.AsSpan(154),
                    PrudpHandshakePacketDecoder.ComputeChecksum(reply.AsSpan(0, 154), 0));
            }
            catch { agreementKey.Dispose(); throw; }
        }

        internal bool TryGetReply(ReadOnlySpan<byte> packet, in PrudpHandshakeMetadata request, out byte[] response)
        {
            response = null;
            // A changed tuple needs a new probe run. Exact retries reuse all key/signature/session bytes.
            if (request.SessionId != clientSession || request.SequenceId != sequence
                || request.ConnectionSignature != clientCookie || request.PublicKeyLength != clientKey.Length
                || !packet.Slice(request.PublicKeyOffset, request.PublicKeyLength).SequenceEqual(clientKey)) return false;
            response = reply;
            return true;
        }

        internal bool MatchesClientSession(byte session) => session == clientSession;

        internal ushort InitialClientDataSequence => unchecked((ushort)(sequence + 1));

        internal byte[] CreateDataPacket(ushort dataSequence, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key) =>
            PrudpDataPacketEncoder.Encode(reply[0], reply[1], reply[3], clientCookie, dataSequence, 0, plaintext, key);

        internal byte[] CreateDataAck(ReadOnlySpan<byte> request) =>
            PrudpDataAckProbeCodec.CreateReply(request, reply[3], clientCookie);

        internal byte[] CreatePingAck(ushort pingSequence)
        {
            byte[] ping = new byte[14];
            ping[0] = reply[0]; ping[1] = reply[1]; ping[2] = 0x0c; ping[3] = reply[3];
            BinaryPrimitives.WriteUInt32LittleEndian(ping.AsSpan(4), clientCookie);
            BinaryPrimitives.WriteUInt16LittleEndian(ping.AsSpan(8), pingSequence);
            BinaryPrimitives.WriteUInt32LittleEndian(ping.AsSpan(10),
                PrudpHandshakePacketDecoder.ComputeChecksum(ping.AsSpan(0, 10), 0));
            return ping;
        }

        internal byte[] DeriveDataKey()
        {
            using ECDiffieHellman peer = ECDiffieHellman.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = clientKey.AsSpan(8, 32).ToArray(), Y = clientKey.AsSpan(40, 32).ToArray() }
            });
            byte[] digest = agreementKey.DeriveKeyFromHash(peer.PublicKey, HashAlgorithmName.SHA1);
            try
            {
                if (digest.Length != 20) throw new CryptographicException("Unexpected SHA-1 KDF size");
                return digest.AsSpan(0, 16).ToArray();
            }
            finally { CryptographicOperations.ZeroMemory(digest); }
        }

        public void Dispose()
        {
            agreementKey.Dispose();
            CryptographicOperations.ZeroMemory(clientKey);
            CryptographicOperations.ZeroMemory(reply);
        }

        private static bool Reject(string reason, out PrudpHandshakeMetadata request, out string rejectionReason)
        {
            request = default;
            rejectionReason = reason;
            return false;
        }
    }

    internal sealed class PrudpProbePeer : IDisposable
    {
        internal uint Cookie { get; init; }
        internal byte SourceVirtualPort { get; init; }
        internal bool SynReplySent { get; set; }
        internal bool ConnectReplySent { get; set; }
        internal PrudpConnectProbe Connect { get; set; }
        public void Dispose() { Connect?.Dispose(); }
    }
}
