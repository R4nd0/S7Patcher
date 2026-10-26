using System;
using System.Buffers.Text;

namespace S7Patcher.Source
{
    // CC5640 formats group:description (System error: decimal) - fixed suffix.
    // Only constants leave this classifier; no caller-provided text is returned.
    internal static class LocalJoinFailureDescription
    {
        internal static string Classify(ReadOnlySpan<byte> text)
        {
            ReadOnlySpan<byte> marker = " (System error: "u8;
            ReadOnlySpan<byte> suffix = ") - No eresult string available."u8;
            if (text.Length > 4096 || !text.EndsWith(suffix)) return "unclassified";
            int separator = text.IndexOf(marker);
            if (separator < 0) return "unclassified";
            var number = text[(separator + marker.Length)..^suffix.Length];
            if (number.IsEmpty || number.Length > 11 || number[0] == (byte)'+'
                || !Utf8Parser.TryParse(number, out long value, out int consumed) || consumed != number.Length
                || value < int.MinValue || value > uint.MaxValue) return "unclassified";
            var prefix = text[..separator];
            int colon = prefix.IndexOf((byte)':');
            if (colon <= 0) return "unclassified";
            // The group is checked too: arbitrary client text cannot become a label.
            var group = prefix[..colon];
            if (!(group.SequenceEqual("General"u8) || group.SequenceEqual("Session"u8)
                || group.SequenceEqual("NetworkEngine"u8) || group.SequenceEqual("PeerChannel"u8)
                || group.SequenceEqual("Link"u8) || group.SequenceEqual("Transport"u8)
                || group.SequenceEqual("MainSocket"u8) || group.SequenceEqual("Transmission"u8)
                || group.SequenceEqual("Services"u8))) return "unclassified";
            var description = prefix[(colon + 1)..];
            if (description.SequenceEqual("Failed"u8)) return "general-failure";
            if (description.SequenceEqual("Failed, because of invalid GUID"u8)) return "invalid-guid";
            if (description.SequenceEqual("Failed, because of timeout"u8)) return "timeout";
            if (description.SequenceEqual("Failed, because of version mismatch"u8)) return "version-mismatch";
            if (description.SequenceEqual("API called with invalid parameter"u8)) return "invalid-parameter";
            if (description.SequenceEqual("API called while module is not initialized"u8)) return "module-not-initialized";
            if (description.SequenceEqual("API called while module is not started"u8)) return "module-not-started";
            if (description.SequenceEqual("API called while module is not in appropriate state"u8)) return "module-state";
            if (description.SequenceEqual("Bind failure"u8)) return "socket-bind";
            if (description.SequenceEqual("Engine not started"u8)) return "engine-not-started";
            if (description.SequenceEqual("Protocol validation failure"u8)) return "protocol-validation";
            if (description.SequenceEqual("Can not unicast to local peer/instance"u8)) return "self-peer";
            if (description.SequenceEqual("Route is not available for specific peer"u8)) return "peer-route-unavailable";
            if (description.SequenceEqual("Invalid session reference id"u8)) return "session-reference";
            if (description.SequenceEqual("Session request refused"u8)) return "session-request-refused";
            if (description.SequenceEqual("Session host gone"u8)) return "session-host-gone";
            if (description.SequenceEqual("Session ticket invalid"u8)) return "session-ticket-invalid";
            if (description.SequenceEqual("Session ticket pending"u8)) return "session-ticket-pending";
            if (description.SequenceEqual("Session invalid"u8)) return "session-invalid";
            if (description.SequenceEqual("Session version mismatch"u8)) return "session-version-mismatch";
            if (description.SequenceEqual("No valid local user account selected or sign-in"u8)) return "local-user-unavailable";
            if (description.SequenceEqual("Link resolve failed"u8)) return "link-resolve-failed";
            if (description.SequenceEqual("Link resolve timeout"u8)) return "link-resolve-timeout";
            if (description.SequenceEqual("Link reach failed"u8)) return "link-reach-failed";
            if (description.SequenceEqual("Link reach refused"u8)) return "link-reach-refused";
            if (description.SequenceEqual("Connection request failed"u8)) return "connection-request-failed";
            if (description.SequenceEqual("Connection reach failed"u8)) return "connection-reach-failed";
            if (description.SequenceEqual("Connection cipher failed"u8)) return "connection-cipher-failed";
            if (description.SequenceEqual("Connection authentication refused"u8)) return "connection-authentication-refused";
            if (description.SequenceEqual("Connection reach refused"u8)) return "connection-reach-refused";
            if (description.SequenceEqual("SMM error, check system error code."u8)) return "matchmaking-service-error";
            return "unclassified";
        }
    }
}
