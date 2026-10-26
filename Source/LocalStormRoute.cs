using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace S7Patcher.Source
{
    // Narrow observed HE descriptor, not a general Storm parser. Native producer
    // D433D0 stores CEBC60's descriptor in #Storm, with no address/port prefix.
    // Only endpoints matching the registered transport's host are projected.
    internal static class LocalStormRoute
    {
        internal static bool TryProject(string text, LocalLoginRpcEngine.RegisteredPeer host,
            out string projected, out string reason)
        {
            projected = null; reason = "local-join-storm-envelope";
            const string prefix = "prudp:/RVCID=", marker = "#Storm=";
            if (text == null || text.Length > 2048 || !text.StartsWith(prefix, StringComparison.Ordinal)
                || host == null || !LocalLoginRpcEngine.PrudpUrl.TryRead(host.PublicUrl, out var registered)) return false;
            int split = text.IndexOf(marker, StringComparison.Ordinal);
            if (split < prefix.Length || text.IndexOf('#') != split || text.LastIndexOf('#') != split) return false;
            reason = "local-join-storm-connection-mismatch";
            if (!TryReadConnection(text.AsSpan(prefix.Length, split - prefix.Length), out uint connection)
                || connection != host.ConnectionId) return false;
            int offset = split + marker.Length;
            string[] names = ["PeerGUID", "Version", "Platform", "Gw", "Address", "PeerDescriptorBaseEnd", "ProfileID", "RoutingOption"];
            Dictionary<string, string> values = new(StringComparer.Ordinal);
            int addressesStart = 0, addressesLength = 0;
            reason = "local-join-storm-descriptor-shape";
            foreach (string name in names)
            {
                string open = name + "{";
                if (!text.AsSpan(offset).StartsWith(open, StringComparison.Ordinal)) return false;
                offset += open.Length;
                int end = text.IndexOf('}', offset);
                if (end < 0) return false;
                string value = text[offset..end];
                foreach (char c in value) if (c is < '!' or > '~' || c is '{' or '#' or ';' or '|' or '%') return false;
                if (name == "Address") { addressesStart = offset; addressesLength = end - offset; }
                values.Add(name, value); offset = end + 1;
            }
            if (offset != text.Length) return false;
            reason = "local-join-storm-descriptor-values";
            if (values["PeerGUID"].Length is < 1 or > 64
                || !Regex.IsMatch(values["PeerGUID"], @"\A[A-Za-z0-9+/_=-]+\z", RegexOptions.CultureInvariant)
                || !ulong.TryParse(values["Version"], NumberStyles.None, CultureInfo.InvariantCulture, out _)
                || !uint.TryParse(values["Platform"], NumberStyles.None, CultureInfo.InvariantCulture, out _)
                || !Regex.IsMatch(values["Gw"], @"\Av\([0-9]\)t\(-\)g\(\)\z", RegexOptions.CultureInvariant)
                || values["PeerDescriptorBaseEnd"] != ""
                // Native C8FB60 accepts an empty ProfileID block. This descriptor
                // field is not the registered identity used to authorize joins.
                || (values["ProfileID"].Length != 0 && !Guid.TryParseExact(values["ProfileID"], "D", out _))
                || !uint.TryParse(values["RoutingOption"], NumberStyles.None, CultureInfo.InvariantCulture, out _)) return false;
            reason = "local-join-storm-endpoints";
            string[] endpoints = values["Address"].Split(',');
            if (endpoints.Length is < 1 or > 16) return false;
            List<string> owned = new();
            HashSet<string> seen = new(StringComparer.Ordinal);
            foreach (string endpoint in endpoints)
            {
                int colon = endpoint.IndexOf(':');
                if (colon <= 0 || colon != endpoint.LastIndexOf(':')) return false;
                string addressText = endpoint[..colon], portText = endpoint[(colon + 1)..];
                if (!IPAddress.TryParse(addressText, out var address) || address.AddressFamily != AddressFamily.InterNetwork
                    || address.ToString() != addressText
                    || !ushort.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out ushort port) || port == 0
                    || port.ToString(CultureInfo.InvariantCulture) != portText || !seen.Add(endpoint)) return false;
                if (address.Equals(registered.Address)) owned.Add(endpoint);
            }
            reason = "local-join-storm-no-owned-endpoint";
            if (owned.Count == 0) return false;
            projected = text[..addressesStart] + string.Join(',', owned) + text[(addressesStart + addressesLength)..];
            reason = "local-join-storm-route-owned";
            return true;
        }

        private static bool TryReadConnection(ReadOnlySpan<char> text, out uint connection)
        {
            connection = 0;
            // StationURL's numeric map holds the same 32 bits but serializes high
            // values as signed decimal. Compare the bits, never discard ownership.
            if (text.StartsWith("-", StringComparison.Ordinal))
            {
                if (!int.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out int signed)
                    || signed >= 0 || !text.SequenceEqual(signed.ToString(CultureInfo.InvariantCulture))) return false;
                connection = unchecked((uint)signed);
                return true;
            }
            return uint.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out connection)
                && connection != 0 && text.SequenceEqual(connection.ToString(CultureInfo.InvariantCulture));
        }
    }
}
