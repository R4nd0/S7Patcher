using System.Buffers.Binary;
using S7Patcher.Source;

internal static class CreationFieldChecks
{
    private static byte[] Ddl(string text) => LocalSessionSearchChecks.Ddl(text);
    private static byte[] Body(byte[] urls, uint scalar, byte flag = 1, int members = 2)
    {
        byte[] number = new byte[4], count = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(number, scalar);
        BinaryPrimitives.WriteUInt32LittleEndian(count, (uint)members);
        byte[] identifiers = Enumerable.Range(0, members * 16).Select(i => (byte)(i % 251)).ToArray();
        // Deliberately distinct from the registration address. Opaque Storm data
        // must survive, but storage does not imply validation for future routing.
        return [0, 0, 0, 0, .. Ddl("invented-space"), 0, 0, 0, 0, .. urls,
            .. count, .. identifiers, .. number, 0, 0, 0, 0, flag];
    }
    internal static int Run()
    {
        int passed = 0;
        void Check(bool value, string label) { if (!value) throw new Exception(label); passed++; }
        const string routes = "prudp:/port=0;RVCID=123#Storm=RoutingOption{invented}|prudp:/port=9999;sid=15";
        byte[] expectedRoutes = System.Text.Encoding.ASCII.GetBytes(routes);
        foreach (uint scalar in new uint[] { 0, 32, uint.MaxValue })
        foreach (byte flag in new byte[] { 0, 1 })
        {
            byte[] body = Body(Ddl(routes), scalar, flag);
            Check(LocalSessionMetadata.TryReadBody(body, true, out _, out _, out var metadata), "Creation fields rejected");
            using (metadata)
            {
                Array.Fill(body, (byte)0); // All retained fields must be owned.
                Check(metadata.Creation.StationUrls.SequenceEqual(expectedRoutes)
                    && metadata.Creation.Scalar == scalar && metadata.Creation.Flag == flag
                    && metadata.Creation.Identifiers.SequenceEqual(Enumerable.Range(0, 32).Select(i => (byte)i).ToArray()),
                    "Creation fields changed or alias request bytes");
                using var clone = metadata.Clone();
                var owned = metadata.Creation;
                ReadOnlySpan<byte> retainedUrls = owned.StationUrls, retainedIds = owned.Identifiers;
                metadata.Dispose();
                Check(retainedUrls.IndexOfAnyExcept((byte)0) < 0 && retainedIds.IndexOfAnyExcept((byte)0) < 0
                    && owned.Scalar == 0 && owned.Flag == 0, "Creation fields not cleared");
                Check(clone.Creation.StationUrls.SequenceEqual(expectedRoutes) && clone.Creation.Scalar == scalar,
                    "Metadata clone shared creation buffers");
            }
        }
        foreach (byte[] empty in new byte[][] { [0, 0], [1, 0, 0] })
        {
            Check(LocalSessionMetadata.TryReadBody(Body(empty, 0, members: 0), true, out _, out _, out var metadata), "Empty creation fields rejected");
            using (metadata) Check(metadata.Creation.StationUrls.IsEmpty && metadata.Creation.Identifiers.IsEmpty,
                "Null/empty native fields became nonempty");
        }
        Check(LocalSessionMetadata.TryReadBody(Body(Ddl(routes), 32, members: 256), true, out _, out _, out var maximum), "Bounded identifier list rejected");
        using (maximum) Check(maximum.Creation.Identifiers.Length == 4096, "Identifier list truncated");
        Check(!LocalSessionMetadata.TryReadBody(Body(Ddl(routes), 32, members: 257), true, out _, out _, out var excess)
            && excess == null, "Excess creation identifiers accepted");
        using var registry = new LocalSessionRegistry();
        using var registration = RegisteredHostChecks.CreateRegistered();
        object owner = new();
        byte[] original = Body(Ddl(routes), 32);
        Check(registry.TryCreate(owner, registration, original, out uint id, out _), "Routing registry setup failed");
        Check(registry.TryUpdate(owner, LocalSessionUpdateChecks.Body(id), out _), "Routing metadata update failed");
        Check(registry.TryGetMetadata(owner, id, out var snapshot), "Routing snapshot missing");
        using (snapshot)
        {
            Check(snapshot.Creation.StationUrls.SequenceEqual(expectedRoutes) && snapshot.Creation.Scalar == 32
                && snapshot.Creation.Flag == 1 && snapshot.Attributes.Count == 1, "Update overwrote game connection fields");
            Check(registry.TryGetHost(owner, id, out var host), "Update lost separate registration");
            using (host) Check(host.PublicUrl.Contains("port=45678") && !host.PublicUrl.Contains("Storm"),
                "Game connection data replaced registration URL");
            Check(registry.TryCreate(owner, registration, original, out uint same, out _) && same == id, "Creation fields broke replay");
            Check(registry.TryLeave(owner, LocalSessionLeaveChecks.Body(id), out _)
                && !registry.TryGetMetadata(owner, id, out _), "Leave retained game routes");
            Check(snapshot.Creation.StationUrls.SequenceEqual(expectedRoutes), "Leave changed caller-owned route snapshot");
        }
        Check(LocalSessionMetadata.TryReadBody(LocalSessionUpdateChecks.Body(), false, out _, out _, out var patch), "Patch fixture failed");
        using (patch) Check(patch.Creation == null, "Update supplied creation-only fields");
        return passed;
    }
}
