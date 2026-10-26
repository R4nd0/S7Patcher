using System;
using System.IO;
using System.Text;
using S7Patcher.Source;

internal static class LocalSessionJoinShapeChecks
{
    private static byte[] Body(uint id = 7, bool reverse = false, bool duplicateClass = false,
        ushort version = 1, int groups = 1, bool duplicateGroup = false, bool duplicateMember = false)
    {
        using MemoryStream stream = new(); using BinaryWriter w = new(stream);
        void Text(string s) { w.Write((ushort)(s.Length + 1)); w.Write(Encoding.ASCII.GetBytes(s)); w.Write((byte)0); }
        w.Write(2u);
        string first = reverse ? "MatchmakingSessionMember" : "MatchmakingSession";
        string second = reverse ? "MatchmakingSession" : "MatchmakingSessionMember";
        Text(first); w.Write(version); Text(duplicateClass ? first : second); w.Write((ushort)1);
        Text("default_session_1"); w.Write(id); w.Write((uint)(duplicateGroup ? 2 : groups));
        for (int i = 0; i < (duplicateGroup ? 2 : Math.Min(groups, 1)); ++i)
        {
            Text("player_setting"); w.Write(duplicateMember ? 2u : 1u);
            for (int m = 0; m < (duplicateMember ? 2 : 1); ++m)
            { w.Write(new byte[] { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 }); w.Write((byte)3); w.Write((byte)1); }
        }
        return stream.ToArray();
    }

    internal static int Run()
    {
        int passed = 0;
        void Check(bool value) { if (!value) throw new Exception("JoinSession_V1 shape regression"); ++passed; }
        foreach (bool reverse in new[] { false, true })
        {
            byte[] body = Body(reverse: reverse);
            Check(LocalSessionMetadata.TryReadJoinBody(body, out var space, out uint id, out var value));
            using (value)
            {
                Check(space.SequenceEqual("default_session_1"u8) && id == 7);
                Check(value.Attributes.Count == 0 && value.Creation == null && value.Members.Count == 1);
                Check(value.Members[Convert.ToHexString("player_setting"u8)]["0102030405060708090A0B0C0D0E0F10"].AsSpan().SequenceEqual(new byte[] { 3,1 }));
                body.AsSpan().Clear();
                Check(value.Members[Convert.ToHexString("player_setting"u8)]["0102030405060708090A0B0C0D0E0F10"][1] == 1);
            }
        }
        byte[] complete = Body();
        for (int length = 0; length < complete.Length; ++length)
        {
            Check(!LocalSessionMetadata.TryReadJoinBody(complete.AsSpan(0, length), out _, out _, out var rejected) && rejected == null);
        }
        foreach (byte[] invalid in new[] { Body(id:0), Body(id:uint.MaxValue), Body(duplicateClass:true), Body(version:2),
            Body(groups:65), Body(duplicateGroup:true), Body(duplicateMember:true), [.. complete, 0], new byte[65537] })
            Check(!LocalSessionMetadata.TryReadJoinBody(invalid, out _, out _, out var rejected) && rejected == null);
        Check(LocalSessionMetadata.TryReadJoinBody(Body(groups:0), out _, out _, out var empty));
        empty.Dispose();
        return passed;
    }
}
