using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace S7Patcher.Source
{
    // Explicit local experiment, not Ubisoft authentication. No socket, logging,
    // account lookup, token decoding or persistence. One instance per transport peer.
    internal sealed class LocalLoginRpcEngine : IDisposable
    {
        internal const int MaximumUrlLength = 512; // Local policy, not a native limit.
        private readonly byte sourceSid;
        private readonly string observedAddress;
        private readonly int observedPort;
        private readonly byte[] profileId = new byte[16];
        private string authenticationUrl, registeredPublicUrl;
        private uint did, rvConnectionId;
        private bool loginHandled, registerHandled, disposed;

        internal LocalLoginRpcEngine(byte clientSourceVirtualPort, IPEndPoint observedLoopbackPeer, string serverAuthUrl, LocalNetworkPolicy network = null)
        {
            network ??= LocalNetworkPolicy.Loopback;
            if (clientSourceVirtualPort >> 4 != 3) throw new ArgumentException("Unsupported local peer stream");
            if (observedLoopbackPeer == null || observedLoopbackPeer.AddressFamily != AddressFamily.InterNetwork
                || !network.Allows(observedLoopbackPeer.Address) || observedLoopbackPeer.Port == 0)
                throw new ArgumentException("A bound explicitly allowed IPv4 peer is required");
            if (!PrudpUrl.TryRead(serverAuthUrl, out PrudpUrl auth) || !network.IsServerAddress(auth.Address)
                || auth.Has("redirected") || (auth.Has("stream") && !auth.NumberIs("stream", 3))
                || (auth.Has("sid") && !auth.NumberIs("sid", 1)))
                throw new ArgumentException("Unsupported local authentication URL");
            sourceSid = (byte)(clientSourceVirtualPort & 15);
            observedAddress = observedLoopbackPeer.Address.ToString();
            observedPort = observedLoopbackPeer.Port;
            try
            {
                do { RandomNumberGenerator.Fill(profileId); } while (ReservedProfile(profileId));
                did = NonzeroRandom(); rvConnectionId = NonzeroRandom();
                authenticationUrl = auth.ReplaceOrAppend("DID", did.ToString(CultureInfo.InvariantCulture));
                if (authenticationUrl.Length > MaximumUrlLength) throw new ArgumentException("Local authentication URL exceeds probe limit");
            }
            catch { Dispose(); throw; }
        }

        // Successful responses are caller-owned and must be zeroed after use.
        // Repeated method calls are explicitly rejected; no argument/token digest,
        // raw request or response cache is retained to recognize retries.
        internal bool TryHandle(ReadOnlySpan<byte> message, out byte[] response, out string fixedReason)
        {
            response = null; fixedReason = "engine-disposed";
            if (disposed) return false;
            if (!LoginRpcCodec.TryReadRequest(message, out LoginRpcRequest request, out LoginRpcFailure headerFailure))
            { fixedReason = "invalid-rpc-header-" + headerFailure.ToString(); return false; }
            if (request.Method == LoginRpcMethod.LoginWithTokenV1 && loginHandled)
            { fixedReason = "login-already-handled"; return false; }
            if (request.Method == LoginRpcMethod.RegisterV1)
            {
                if (!loginHandled) { fixedReason = "registration-before-login"; return false; }
                if (registerHandled) { fixedReason = "registration-already-handled"; return false; }
            }
            ReadOnlySpan<byte> body = message.Slice(request.BodyOffset, request.BodyLength);
            if (!LoginRpcArgumentShape.TryValidate(request.Method, body, out LoginRpcArgumentShapeFailure shapeFailure))
            { fixedReason = "invalid-rpc-arguments-" + shapeFailure.ToString(); return false; }
            if (request.Method == LoginRpcMethod.LoginWithTokenV1)
            {
                if (!LoginRpcCodec.TryWriteLoginSuccess(request.CallId, new(profileId, authenticationUrl, false), out response, out _))
                { fixedReason = "response-encoding-failed"; return false; }
                loginHandled = true; fixedReason = "local-login-response-created"; return true;
            }
            if (!TrySelectPublicUrl(body, out string publicUrl))
            { fixedReason = "no-supported-registration-url"; return false; }
            if (!LoginRpcCodec.TryWriteRegisterSuccess(request.CallId, new(rvConnectionId, publicUrl), out response, out _))
            { fixedReason = "response-encoding-failed"; return false; }
            registeredPublicUrl = publicUrl;
            registerHandled = true; fixedReason = "local-register-response-created"; return true;
        }

        // Export only completed local registration state, never request-supplied
        // member GUIDs. The transport still gates session operations on its ACK.
        internal bool TryCopyRegisteredPeer(out RegisteredPeer peer)
        {
            peer = null;
            if (disposed || !registerHandled) return false;
            peer = new(profileId, rvConnectionId, registeredPublicUrl);
            return true;
        }

        internal sealed class RegisteredPeer : IDisposable
        {
            private readonly byte[] profile;
            internal ReadOnlySpan<byte> ProfileId => profile;
            internal uint ConnectionId { get; private set; }
            internal string PublicUrl { get; private set; }
            internal RegisteredPeer(ReadOnlySpan<byte> profileId, uint connectionId, string publicUrl)
            { profile = profileId.ToArray(); ConnectionId = connectionId; PublicUrl = publicUrl; }
            internal RegisteredPeer Clone()
            {
                if (PublicUrl == null) throw new ObjectDisposedException(nameof(RegisteredPeer));
                return new(profile, ConnectionId, PublicUrl);
            }
            internal bool Matches(RegisteredPeer other) => other != null && PublicUrl != null
                && ConnectionId == other.ConnectionId && PublicUrl == other.PublicUrl
                && ProfileId.SequenceEqual(other.ProfileId);
            public void Dispose()
            {
                CryptographicOperations.ZeroMemory(profile);
                ConnectionId = 0; PublicUrl = null;
            }
        }

        private bool TrySelectPublicUrl(ReadOnlySpan<byte> body, out string publicUrl)
        {
            publicUrl = null;
            // Prior shape validation proves empty u32 map + u32 count + exact DDLs.
            uint count = BinaryPrimitives.ReadUInt32LittleEndian(body[4..]);
            int offset = 8;
            for (uint index = 0; index < count; index++)
            {
                int length = BinaryPrimitives.ReadUInt16LittleEndian(body[offset..]); offset += 2;
                // Native DDL null is structurally valid, but cannot be selected as
                // a public URL. Do not subtract the missing terminator from zero.
                if (length == 0) continue;
                ReadOnlySpan<byte> raw = body.Slice(offset, length - 1); offset += length;
                if (raw.Length > MaximumUrlLength || !PrudpUrl.IsSupportedAscii(raw)) continue;
                // Only URL strings are decoded. Login arguments never reach here.
                if (!PrudpUrl.TryRead(Encoding.ASCII.GetString(raw), out PrudpUrl candidate)
                    || !candidate.NumberIs("sid", sourceSid)
                    || (candidate.Has("stream") && !candidate.NumberIs("stream", 3))) continue;
                string rewritten = candidate.ReplaceAddressAndPort(observedAddress, observedPort);
                if (rewritten.Length > MaximumUrlLength) continue;
                publicUrl = rewritten; return true;
            }
            return false;
        }

        private static uint NonzeroRandom()
        {
            Span<byte> bytes = stackalloc byte[4]; uint value;
            do { RandomNumberGenerator.Fill(bytes); value = BinaryPrimitives.ReadUInt32LittleEndian(bytes); } while (value == 0);
            CryptographicOperations.ZeroMemory(bytes); return value;
        }
        private static bool ReservedProfile(ReadOnlySpan<byte> value)
        {
            for (int index = 0; index < 15; index++) if (value[index] != 0) return false;
            return value[15] is 0 or 2; // Null and the native special-profile sentinel.
        }
        public void Dispose()
        {
            if (disposed) return;
            disposed = true; CryptographicOperations.ZeroMemory(profileId);
            did = 0; rvConnectionId = 0; authenticationUrl = null; registeredPublicUrl = null;
        }

        // Supported subset: prudp:/key=value pairs, semicolon separated, unique
        // case-insensitive keys, no '#' section/escaping/empty segments. Preserve
        // accepted original pairs and ordering; replace only requested fields.
        internal sealed class PrudpUrl
        {
            private readonly string[] pairs;
            private readonly Dictionary<string, int> positions;
            internal IPAddress Address { get; }
            private PrudpUrl(string[] pairs, Dictionary<string, int> positions, IPAddress address)
            { this.pairs = pairs; this.positions = positions; Address = address; }
            internal bool Has(string name) => positions.ContainsKey(name);
            private string Value(string name)
            {
                if (!positions.TryGetValue(name, out int index)) return null;
                string pair = pairs[index]; return pair[(pair.IndexOf('=') + 1)..];
            }
            internal bool NumberIs(string name, uint expected) => uint.TryParse(Value(name), NumberStyles.None,
                CultureInfo.InvariantCulture, out uint number) && number == expected;
            internal string ReplaceOrAppend(string name, string value)
            {
                List<string> rewritten = new(pairs);
                if (positions.TryGetValue(name, out int index)) rewritten[index] = name + "=" + value;
                else rewritten.Add(name + "=" + value);
                return "prudp:/" + string.Join(";", rewritten);
            }
            internal string ReplaceAddressAndPort(string address, int port)
            {
                string[] rewritten = (string[])pairs.Clone();
                rewritten[positions["address"]] = "address=" + address;
                rewritten[positions["port"]] = "port=" + port.ToString(CultureInfo.InvariantCulture);
                return "prudp:/" + string.Join(";", rewritten);
            }
            internal static bool IsSupportedAscii(ReadOnlySpan<byte> text)
            {
                foreach (byte value in text) if (value is < 0x21 or > 0x7e) return false;
                return true;
            }
            // Game StationURL only. E5E465..E5E4AE splits one '#' and parses the
            // suffix into a separate string map (+0x20), not the routing address.
            // Return only the parsed base for ownership checks. The caller retains
            // and transmits the original full string; never rebuild it from this view.
            // Login/Register deliberately continue using the narrower TryRead.
            internal static bool TryReadGameRoute(string text, out PrudpUrl url)
            {
                url = null;
                if (text == null || text.Length > MaximumUrlLength) return false;
                int separator = text.IndexOf('#');
                if (separator < 0) return TryRead(text, out url);
                if (separator != text.LastIndexOf('#') || separator == text.Length - 1
                    || !TryRead(text[..separator], out var primary)) return false;
                HashSet<string> names = new(primary.positions.Keys, StringComparer.OrdinalIgnoreCase);
                foreach (string pair in text[(separator + 1)..].Split(';'))
                {
                    int equals = pair.IndexOf('=');
                    if (equals <= 0 || equals != pair.LastIndexOf('=') || equals == pair.Length - 1) return false;
                    foreach (char value in pair)
                        if (value is < '!' or > '~' || value is '#' or '%' or '?' or '\\' or '|') return false;
                    string name = pair[..equals];
                    foreach (char value in name) if (!char.IsAsciiLetterOrDigit(value) && value != '_') return false;
                    if (!names.Add(name)) return false;
                    // Conservative local policy: no routing aliases or redirect
                    // markers hidden in the separate custom-data section.
                    foreach (string routing in new[] { "address", "port", "sid", "stream", "redirected" })
                        if (name.Equals(routing, StringComparison.OrdinalIgnoreCase)) return false;
                }
                url = primary;
                return true;
            }
            internal static bool TryRead(string text, out PrudpUrl url)
            {
                url = null;
                if (text == null || text.Length > MaximumUrlLength || !text.StartsWith("prudp:/", StringComparison.Ordinal)) return false;
                foreach (char value in text) if (value is < '!' or > '~' || value is '#' or '%' or '?' or '\\' or '|') return false;
                string[] pairs = text[7..].Split(';');
                Dictionary<string, int> positions = new(StringComparer.OrdinalIgnoreCase);
                for (int index = 0; index < pairs.Length; index++)
                {
                    string pair = pairs[index]; int equals = pair.IndexOf('=');
                    if (equals <= 0 || equals != pair.LastIndexOf('=') || equals == pair.Length - 1) return false;
                    string name = pair[..equals];
                    foreach (char value in name) if (!char.IsAsciiLetterOrDigit(value) && value != '_') return false;
                    if (!positions.TryAdd(name, index)) return false;
                    // Routing names are case-sensitive in the inspected native getter.
                    foreach (string routing in new[] { "address", "port", "sid", "stream" })
                        if (name.Equals(routing, StringComparison.OrdinalIgnoreCase) && name != routing) return false;
                }
                if (!positions.TryGetValue("address", out int addressIndex) || !positions.TryGetValue("port", out int portIndex)) return false;
                string addressText = pairs[addressIndex][(pairs[addressIndex].IndexOf('=') + 1)..];
                string portText = pairs[portIndex][(pairs[portIndex].IndexOf('=') + 1)..];
                if (!IPAddress.TryParse(addressText, out IPAddress address) || address.AddressFamily != AddressFamily.InterNetwork
                    || !int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out int port) || port is < 1 or > 65535) return false;
                url = new(pairs, positions, address); return true;
            }
        }
    }
}
