using System.Buffers.Binary;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using S7Patcher.Source;

int passed = 0;
void Check(bool condition, string message) { if (!condition) throw new Exception(message); passed++; }
const string auth = "prudp:/address=127.0.0.1;port=9111;stream=3;sid=1;type=2";
const string ordinary = "prudp:/address=10.1.2.3;port=1234;sid=10";
static void Ddl(BinaryWriter writer, byte[] bytes) { writer.Write((ushort)(bytes.Length + 1)); writer.Write(bytes); writer.Write((byte)0); }
static byte[] Request(string method, uint callId, byte[] body)
{
    using MemoryStream output = new(); using BinaryWriter writer = new(output);
    writer.Write(0u); Ddl(writer, Encoding.ASCII.GetBytes("LoginProtocol")); writer.Write((byte)1); writer.Write(callId);
    Ddl(writer, Encoding.ASCII.GetBytes("LoginProtocol::" + method)); writer.Write(body);
    byte[] result = output.ToArray(); BinaryPrimitives.WriteUInt32LittleEndian(result, (uint)(result.Length - 4)); return result;
}
static byte[] Login(uint callId = 0x12345678)
{
    using MemoryStream output = new(); using BinaryWriter writer = new(output);
    writer.Write(1u); Ddl(writer, Encoding.ASCII.GetBytes("ClientVersionInfo")); writer.Write((ushort)1);
    // Deliberately nontext token: only its DDL extent may be inspected.
    Ddl(writer, [0, 0xff, 0x80, 0x41]); writer.Write(new byte[10]); writer.Write((byte)0); Ddl(writer, []);
    return Request("LoginWithToken_V1", callId, output.ToArray());
}
static byte[] Register(params string[] urls)
{
    using MemoryStream output = new(); using BinaryWriter writer = new(output);
    writer.Write(0u); writer.Write((uint)urls.Length);
    foreach (string url in urls) Ddl(writer, Encoding.UTF8.GetBytes(url));
    return Request("Register_V1", 0xabcdef01, output.ToArray());
}
LocalLoginRpcEngine Engine(string url = auth) => new(0x3a, new(IPAddress.Loopback, 45678), url);
static string ReadDdl(byte[] response, ref int offset)
{
    int length = BinaryPrimitives.ReadUInt16LittleEndian(response.AsSpan(offset)); offset += 2;
    if (length < 1 || offset + length > response.Length || response[offset + length - 1] != 0) throw new Exception("Malformed response string");
    string result = Encoding.ASCII.GetString(response, offset, length - 1); offset += length; return result;
}
int ResponseStart(byte[] response, string method, uint callId)
{
    Check(BinaryPrimitives.ReadUInt32LittleEndian(response) == response.Length - 4, "Response outer length differs");
    int offset = 4; Check(ReadDdl(response, ref offset) == "LoginProtocol", "Response protocol differs");
    Check(response[offset++] == 0 && response[offset++] == 1, "Response flag/result discriminator differ");
    Check(BinaryPrimitives.ReadUInt32LittleEndian(response.AsSpan(offset)) == callId, "Call ID was not echoed"); offset += 4;
    Check(ReadDdl(response, ref offset) == "LoginProtocol::" + method + "*", "Exact starred response method differs");
    return offset;
}
byte[] OwnedProfile(LocalLoginRpcEngine engine) => (byte[])typeof(LocalLoginRpcEngine).GetField("profileId", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(engine)!;
uint OwnedNumber(LocalLoginRpcEngine engine, string name) => (uint)typeof(LocalLoginRpcEngine).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(engine)!;
void Reject(LocalLoginRpcEngine engine, byte[] message, string expected)
{
    Check(!engine.TryHandle(message, out byte[] response, out string reason) && response == null && reason == expected,
        "Rejection reason/output differs from fixed expected category");
}
void DoLogin(LocalLoginRpcEngine engine)
{
    Check(engine.TryHandle(Login(), out byte[] reply, out string reason) && reason == "local-login-response-created", "Valid synthetic Login rejected");
    CryptographicOperations.ZeroMemory(reply);
}
string DoRegister(LocalLoginRpcEngine engine, params string[] urls)
{
    Check(engine.TryHandle(Register(urls), out byte[] reply, out string reason) && reason == "local-register-response-created", "Valid synthetic Register rejected");
    int offset = ResponseStart(reply, "Register_V1", 0xabcdef01);
    Check(BinaryPrimitives.ReadUInt32LittleEndian(reply.AsSpan(offset)) == OwnedNumber(engine, "rvConnectionId")
        && OwnedNumber(engine, "rvConnectionId") != 0, "Register RVCID changed or is zero"); offset += 4;
    string url = ReadDdl(reply, ref offset); Check(offset == reply.Length && reply.Length < 947, "Register response has extra fields or exceeds single probe fragment");
    CryptographicOperations.ZeroMemory(reply); return url;
}

using (LocalLoginRpcEngine engine = Engine())
{
    Reject(engine, Register(ordinary), "registration-before-login");
    byte[] request = Login(), hash = SHA256.HashData(request);
    Check(engine.TryHandle(request, out byte[] reply, out string reason) && reason == "local-login-response-created", "Login shape not accepted");
    Check(SHA256.HashData(request).SequenceEqual(hash), "Login engine mutated input");
    int offset = ResponseStart(reply, "LoginWithToken_V1", 0x12345678);
    byte[] profile = reply.AsSpan(offset, 16).ToArray(); offset += 16;
    Check(profile.SequenceEqual(OwnedProfile(engine)) && profile.Any(value => value != 0)
        && !profile.SequenceEqual(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 }), "Profile not owned random nonreserved raw16");
    string loginUrl = ReadDdl(reply, ref offset);
    Check(OwnedNumber(engine, "did") != 0 && loginUrl == auth + ";DID=" + OwnedNumber(engine, "did"), "Login target changed or DID not stable/nonzero");
    Check(reply[offset++] == 0 && offset == reply.Length && !loginUrl.Contains("redirected"), "Login invented redirect or extra fields");
    Reject(engine, request, "login-already-handled"); Reject(engine, Login(99), "login-already-handled");
    string publicUrl = DoRegister(engine, ordinary);
    Check(publicUrl == "prudp:/address=127.0.0.1;port=45678;sid=10", "Register failed observed endpoint replacement or added stream/type");
    Check(profile.SequenceEqual(OwnedProfile(engine)), "Registration mutated local identity");
    Reject(engine, Register(ordinary), "registration-already-handled");
    CryptographicOperations.ZeroMemory(profile); CryptographicOperations.ZeroMemory(reply);
}
using (LocalLoginRpcEngine engine = Engine(auth + ";DID=5"))
{
    Check(engine.TryHandle(Login(), out byte[] reply, out _), "Existing auth DID not replaceable");
    int offset = ResponseStart(reply, "LoginWithToken_V1", 0x12345678) + 16;
    string url = ReadDdl(reply, ref offset);
    Check(url == auth + ";DID=" + OwnedNumber(engine, "did") && url.Split("DID=").Length == 2, "Auth DID duplicated instead of replaced");
    CryptographicOperations.ZeroMemory(reply);
    string candidate = "prudp:/sid=10;custom=a-b_12:/+;port=9;address=192.168.5.1;type=0;stream=3;DID=7;RVCID=8";
    Check(DoRegister(engine, "prudp:/address=127.0.0.1;port=9;sid=11", candidate, ordinary)
        == "prudp:/sid=10;custom=a-b_12:/+;port=45678;address=127.0.0.1;type=0;stream=3;DID=7;RVCID=8", "First matching original URL attributes/order not preserved");
}
using (LocalLoginRpcEngine engine = Engine())
{
    byte[] valid = Login();
    for (int length = 0; length < valid.Length; length++)
    {
        byte[] truncated = valid[..length]; if (length >= 4) BinaryPrimitives.WriteUInt32LittleEndian(truncated, (uint)(length - 4));
        Check(!engine.TryHandle(truncated, out byte[] output, out string reason) && output == null
            && (Enum.GetNames<LoginRpcFailure>().Any(name => reason == "invalid-rpc-header-" + name)
                || Enum.GetNames<LoginRpcArgumentShapeFailure>().Any(name => reason == "invalid-rpc-arguments-" + name)), "Truncated Login accepted or leaked arbitrary reason");
    }
    byte[] oldMap = Request("LoginWithToken_V1", 1, new byte[32]); Reject(engine, oldMap, "invalid-rpc-arguments-UnsupportedExtensionMap");
    byte[] unknown = Request("Unknown_test_secret", 1, [1, 2, 3]); Reject(engine, unknown, "invalid-rpc-header-UnknownMethod");
    DoLogin(engine); Reject(engine, Register(), "invalid-rpc-arguments-UrlCountOutOfRange");
    Reject(engine, Request("Register_V1", 1, [0, 0, 0, 0, 1, 0, 0, 0, 0, 0]), "no-supported-registration-url");
    Reject(engine, Register(Enumerable.Repeat(ordinary, 33).ToArray()), "invalid-rpc-arguments-UrlCountOutOfRange");
    Check(DoRegister(engine, Enumerable.Repeat(ordinary, 32).ToArray()).EndsWith("sid=10"), "Maximum supported URL count rejected");
}
string[] invalidUrls = [
    "", "http://127.0.0.1", "prudp:/address=127.0.0.1;port=9", ordinary + ";sid=10", ordinary + ";SID=10",
    ordinary + "#x=y", ordinary + ";x=%20", ordinary + ";x=?a", ordinary + ";x=\\a", ordinary + ";x=with space",
    ordinary + ";x=a=b", ordinary + ";", ordinary + ";x=", ordinary + ";=x", ordinary + ";x=\0secret",
    ordinary + ";x=ü", "prudp:/address=localhost;port=9;sid=10", "prudp:/address=::1;port=9;sid=10",
    "prudp:/address=127.0.0.1;port=0;sid=10", "prudp:/address=127.0.0.1;port=65536;sid=10",
    "prudp:/address=127.0.0.1;port=9;sid=11", ordinary + ";stream=2", ordinary + ";stream=9999999999999999999",
    ordinary + ";x=" + new string('a', 512)
];
foreach (string url in invalidUrls)
{
    using LocalLoginRpcEngine engine = Engine(); DoLogin(engine);
    Reject(engine, Register(url), "no-supported-registration-url");
    Check(DoRegister(engine, ordinary) == "prudp:/address=127.0.0.1;port=45678;sid=10", "Failed URL consumed registration slot");
}
using (LocalLoginRpcEngine engine = Engine())
{
    DoLogin(engine);
    Check(DoRegister(engine, ordinary + "#unsupported", ordinary) == "prudp:/address=127.0.0.1;port=45678;sid=10", "Unsupported entry prevented selecting first supported URL");
}
using (LocalLoginRpcEngine engine = Engine())
{
    DoLogin(engine);
    using MemoryStream output = new(); using BinaryWriter writer = new(output);
    writer.Write(0u); writer.Write(2u); writer.Write((ushort)0); Ddl(writer, Encoding.ASCII.GetBytes(ordinary));
    Check(engine.TryHandle(Request("Register_V1", 0xabcdef01, output.ToArray()), out byte[] response, out _), "Null DDL entry prevented later supported URL selection");
    int offset = ResponseStart(response, "Register_V1", 0xabcdef01) + 4;
    Check(ReadDdl(response, ref offset) == "prudp:/address=127.0.0.1;port=45678;sid=10", "Null DDL skip used wrong next field offset");
    CryptographicOperations.ZeroMemory(response);
}
using (LocalLoginRpcEngine engine = Engine())
{
    DoLogin(engine); string prefix = "prudp:/address=127.0.0.1;port=45678;sid=10;x=";
    string maximum = prefix + new string('a', 512 - prefix.Length);
    Reject(engine, Register(maximum + "x"), "no-supported-registration-url");
    Check(DoRegister(engine, maximum) == maximum, "Exact512-byte preserved URL rejected");
}
void RejectConstructor(Action create)
{
    try { create(); throw new Exception("Unsupported constructor context accepted"); }
    catch (ArgumentException exception) { Check(!exception.Message.Contains("test-secret"), "Constructor exception leaked URL values"); }
}
foreach (string invalidAuth in new[] { auth + ";redirected=true", auth + ";redirected=", auth + ";address=127.0.0.1",
    "prudp:/address=192.0.2.1;port=9;sid=1", "prudp:/address=127.0.0.1;port=9;sid=2",
    auth + ";test-secret=" + new string('x', 512) }) RejectConstructor(() => { using var ignored = Engine(invalidAuth); });
RejectConstructor(() => { using var ignored = new LocalLoginRpcEngine(0x2a, new(IPAddress.Loopback, 9), auth); });
RejectConstructor(() => { using var ignored = new LocalLoginRpcEngine(0x3a, new(IPAddress.Parse("192.0.2.1"), 9), auth); });
RejectConstructor(() => { using var ignored = new LocalLoginRpcEngine(0x3a, new(IPAddress.IPv6Loopback, 9), auth); });
RejectConstructor(() => { using var ignored = new LocalLoginRpcEngine(0x3a, new(IPAddress.Loopback, 0), auth); });

TextWriter originalOut = Console.Out, originalError = Console.Error;
using StringWriter captured = new();
LocalLoginRpcEngine disposed = Engine(); byte[] ownedBeforeDispose = OwnedProfile(disposed);
try
{
    Console.SetOut(captured); Console.SetError(captured);
    DoLogin(disposed); DoRegister(disposed, ordinary); disposed.Dispose(); disposed.Dispose();
    Reject(disposed, Login(), "engine-disposed");
}
finally { Console.SetOut(originalOut); Console.SetError(originalError); disposed.Dispose(); }
Check(captured.ToString() == "", "Engine logged account, URL or response material");
Check(ownedBeforeDispose.All(value => value == 0) && OwnedNumber(disposed, "did") == 0 && OwnedNumber(disposed, "rvConnectionId") == 0, "Dispose retained owned identity material");
Console.WriteLine($"PASS: {passed} isolated local-login engine checks; exact schema, stage order, local identity, URL preservation/bounds, fixed rejections, opaque token and zeroing. No network integration.");
