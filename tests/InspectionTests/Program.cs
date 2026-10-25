using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

if (args.Length is < 2 or > 3) throw new ArgumentException("Supply dotnet path, S7Patcher.dll path, and optionally a real game installation.");
string dotnet = Path.GetFullPath(args[0]);
string patcher = Path.GetFullPath(args[1]);
string cases = Path.Combine(AppContext.BaseDirectory, "cases-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(cases);
int passed = 0;

string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
void Check(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}
JsonElement Run(int expectedCode, params string[] arguments)
{
    ProcessStartInfo start = new(dotnet) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
    start.ArgumentList.Add(patcher);
    foreach (string argument in arguments) start.ArgumentList.Add(argument);
    using Process process = Process.Start(start) ?? throw new Exception("Could not start CLI");
    Task<string> stdout = process.StandardOutput.ReadToEndAsync();
    Task<string> stderr = process.StandardError.ReadToEndAsync();
    if (!process.WaitForExit(15000)) { process.Kill(); throw new Exception("CLI hung instead of returning"); }
    string output = stdout.GetAwaiter().GetResult();
    Check(process.ExitCode == expectedCode, $"Expected exit {expectedCode}, got {process.ExitCode}: {output} {stderr.GetAwaiter().GetResult()}");
    JsonElement report = JsonDocument.Parse(output).RootElement.Clone();
    Check(report.GetProperty("exitCode").GetInt32() == expectedCode, "Exit code differs from report");
    Check(!report.GetProperty("lanCompatibilityVerified").GetBoolean(), "Inspection must not claim LAN is verified");
    passed++;
    return report;
}
string RunDiagnostic(int expectedCode, params string[] arguments)
{
    ProcessStartInfo start = new(dotnet) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
    start.ArgumentList.Add(patcher);
    foreach (string argument in arguments) start.ArgumentList.Add(argument);
    using Process process = Process.Start(start) ?? throw new Exception("Could not start CLI");
    Task<string> stdout = process.StandardOutput.ReadToEndAsync();
    Task<string> stderr = process.StandardError.ReadToEndAsync();
    if (!process.WaitForExit(30000)) { process.Kill(); throw new Exception("Diagnostic CLI hung instead of returning"); }
    string output = stdout.GetAwaiter().GetResult();
    Check(process.ExitCode == expectedCode, $"Expected diagnostic exit {expectedCode}, got {process.ExitCode}: {output} {stderr.GetAwaiter().GetResult()}");
    passed++;
    return output;
}

if (args.Length == 3)
{
string game = Path.GetFullPath(args[2]);
string realExe = new[] { Path.Combine(game, "Base", "Bin", "Settlers7R.exe"), Path.Combine(game, "Data", "Base", "Bin", "Settlers7R.exe") }.Single(File.Exists);
string originalHash = Hash(realExe);
DateTime originalModified = File.GetLastWriteTimeUtc(realExe);
string[] originalFiles = Directory.GetFileSystemEntries(Path.GetDirectoryName(realExe)!).Order().ToArray();
JsonElement known = Run(0, "--inspect", game);
Check(known.GetProperty("recognizedBuild").GetBoolean(), "Actual known build was not recognized");
Check(known.GetProperty("executable").GetProperty("sha256").GetString() == originalHash.ToLowerInvariant(), "Reported hash mismatch");
Check(known.GetProperty("networkLibraries").EnumerateArray().Any(item => item.GetProperty("name").GetString() == "uplay_r1_loader.dll"), "Missing Uplay loader inventory");
Run(0, "--inspect", realExe);
Check(Hash(realExe) == originalHash && File.GetLastWriteTimeUtc(realExe) == originalModified, "Inspection modified actual game executable");
Check(Directory.GetFileSystemEntries(Path.GetDirectoryName(realExe)!).Order().SequenceEqual(originalFiles), "Inspection created a game-side file or backup");
}

string unknown = Path.Combine(cases, "unknown.exe");
File.WriteAllBytes(unknown, [0x4D, 0x5A, 0x00, 0x01, 0x02]);
string unknownHash = Hash(unknown);
Run(3, "--inspect", unknown);
Check(Hash(unknown) == unknownHash, "Unknown input was changed");
Run(2, "--inspect", Path.Combine(cases, "missing.exe"));
Run(2, "--inspect");
Run(2, "--inspect", unknown, "--debug");
Run(2, unknown, "--inspect");
Run(2, "--inspect=" + unknown);
Check(!File.Exists(Path.Combine(cases, "unknown_BACKUP.exe")), "Malformed inspection fell through into patching");

string baseRoot = Path.Combine(cases, "base-layout");
string baseExe = Path.Combine(baseRoot, "Base", "Bin", "Settlers7R.exe");
Directory.CreateDirectory(Path.GetDirectoryName(baseExe)!);
File.Copy(unknown, baseExe);
Check(Run(3, "--inspect", baseRoot).GetProperty("executable").GetProperty("path").GetString() == baseExe, "Base/Bin layout not resolved");
string dataRoot = Path.Combine(cases, "data-layout");
string dataExe = Path.Combine(dataRoot, "Data", "Base", "Bin", "Settlers7R.exe");
Directory.CreateDirectory(Path.GetDirectoryName(dataExe)!);
File.Copy(unknown, dataExe);
Check(Run(3, "--inspect", dataRoot).GetProperty("executable").GetProperty("path").GetString() == dataExe, "Data/Base/Bin layout not resolved");
string ambiguous = Path.Combine(baseRoot, "Data", "Base", "Bin", "Settlers7R.exe");
Directory.CreateDirectory(Path.GetDirectoryName(ambiguous)!);
File.Copy(unknown, ambiguous);
Run(2, "--inspect", baseRoot);
if (OperatingSystem.IsWindows())
{
    using FileStream locked = new(unknown, FileMode.Open, FileAccess.Read, FileShare.None);
    Run(1, "--inspect", unknown);
}
RunDiagnostic(2, "--lan-experiment");
RunDiagnostic(2, "--lan-experiment=prepare");
string rejectedOutput = Path.Combine(cases, "rejected-output");
RunDiagnostic(2, "--lan-experiment", "prepare", Path.Combine(cases, "missing-game"), "--output", rejectedOutput);
Check(!Directory.Exists(rejectedOutput), "Invalid input created a diagnostic output");
if (args.Length == 3)
{
    string output = Path.Combine(cases, "staged-diagnostic");
    JsonElement diagnostic = JsonDocument.Parse(RunDiagnostic(0, "--lan-experiment", "prepare", args[2], "--output", output)).RootElement;
    Check(!diagnostic.GetProperty("installed").GetBoolean(), "Diagnostic must not install itself");
    Check(!diagnostic.GetProperty("lan_compatibility_verified").GetBoolean(), "Diagnostic must not claim playable LAN");
    RunDiagnostic(2, "--lan-experiment", "prepare", args[2], "--output", output);
}
Console.WriteLine($"PASS: {passed} CLI cases. Inspection inputs unchanged and unsafe diagnostic actions rejected.");
