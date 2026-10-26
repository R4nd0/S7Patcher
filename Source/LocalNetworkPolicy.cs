using System;
using System.Net;
using System.Net.Sockets;

namespace S7Patcher.Source
{
    // Explicit two-machine experiment. Never permits a subnet, wildcard or DNS name.
    internal sealed class LocalNetworkPolicy
    {
        internal static LocalNetworkPolicy Loopback { get; } = new(IPAddress.Loopback, null);
        internal IPAddress BindAddress { get; }
        internal IPAddress PeerAddress { get; }
        internal bool IsLan => PeerAddress != null;
        private LocalNetworkPolicy(IPAddress local, IPAddress peer) { BindAddress = local; PeerAddress = peer; }

        internal static bool TryCreate(string local, string peer, out LocalNetworkPolicy policy)
        {
            policy = null;
            if (!TryPrivateAddress(local, out var left) || !TryPrivateAddress(peer, out var right) || left.Equals(right)) return false;
            policy = new(left, right); return true;
        }

        internal static bool TryPrivateAddress(string text, out IPAddress address)
        {
            address = null;
            if (text == null || !IPAddress.TryParse(text, out var candidate)
                || candidate.AddressFamily != AddressFamily.InterNetwork || candidate.ToString() != text) return false;
            byte[] b = candidate.GetAddressBytes();
            // Reject conventional network/broadcast addresses too; no subnet inference.
            if (b[3] is 0 or 255 || !(b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31)
                || (b[0] == 192 && b[1] == 168))) return false;
            address = candidate; return true;
        }

        internal bool Allows(IPAddress address) => address != null && address.AddressFamily == AddressFamily.InterNetwork
            && (IPAddress.IsLoopback(address) || BindAddress.Equals(address) || (PeerAddress?.Equals(address) ?? false));
        internal bool IsServerAddress(IPAddress address) => BindAddress.Equals(address);
    }
}
