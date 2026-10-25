using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace S7Patcher.Source
{
    // This entry point deliberately does not use the existing patching helpers:
    // those create backups and open the executable with write access.
    internal static class InspectionCommand
    {
        internal const string KnownHistoryUbisoftSha256 = "4ef51632a8a193050ebe8ef3f3fe38a9b240b4aa57ff62a4f381bc0f539df64f";

        internal static bool TryRun(string[] args, out int exitCode)
        {
            exitCode = 0;
            if (!args.Any(value => value.StartsWith("--inspect", StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }

            // Malformed inspection requests must never fall through into patching.
            exitCode = Run(args, Console.Out);
            return true;
        }

        internal static int Run(string[] args, TextWriter output)
        {
            InspectionReport report = new();
            int exitCode;

            if (args.Length != 2 || !args[0].Equals("--inspect", StringComparison.OrdinalIgnoreCase)
                || string.IsNullOrWhiteSpace(args[1]))
            {
                report.Error = "Usage: S7Patcher --inspect <Settlers7R.exe or installation folder>";
                return WriteReport(report, 2, output);
            }

            try
            {
                report.Input = Path.GetFullPath(args[1]);
                string executable = ResolveExecutable(report.Input);
                report.Executable = InspectBinary(executable);
                report.RecognizedBuild = string.Equals(report.Executable.Sha256, KnownHistoryUbisoftSha256, StringComparison.Ordinal);
                report.Edition = report.RecognizedBuild ? "History Edition - Ubisoft Connect" : "Unknown / unsupported executable fingerprint";
                report.Status = report.RecognizedBuild ? "recognized" : "unsupported-build";

                string binaryDirectory = Path.GetDirectoryName(executable);
                foreach (string path in Directory.EnumerateFiles(binaryDirectory).OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
                {
                    if (IsRelevantDependency(Path.GetFileName(path)))
                    {
                        report.NetworkLibraries.Add(InspectBinary(path));
                    }
                }

                report.Notes.Add("Executable recognition identifies a build; it does not establish working LAN or replacement-server compatibility.");
                report.Notes.Add("Inspection only reads the selected executable and relevant libraries beside it. No backup, patch, configuration change, download or game launch is performed.");
                exitCode = report.RecognizedBuild ? 0 : 3;
            }
            catch (InspectionInputException exception)
            {
                report.Error = exception.Message;
                exitCode = 2;
            }
            catch (Exception exception) when (exception is ArgumentException || exception is NotSupportedException || exception is PathTooLongException)
            {
                report.Error = "Invalid inspection path: " + exception.Message;
                exitCode = 2;
            }
            catch (Exception exception) when (exception is IOException || exception is UnauthorizedAccessException || exception is Win32Exception)
            {
                report.Error = "Could not complete read-only inspection: " + exception.Message;
                exitCode = 1;
            }

            return WriteReport(report, exitCode, output);
        }

        private static int WriteReport(InspectionReport report, int exitCode, TextWriter output)
        {
            report.ExitCode = exitCode;
            if (report.Error != null)
            {
                report.Status = "error";
            }
            output.WriteLine(JsonSerializer.Serialize(report, InspectionJsonContext.Default.InspectionReport));
            return exitCode;
        }

        private static string ResolveExecutable(string input)
        {
            if (File.Exists(input))
            {
                return input;
            }
            if (!Directory.Exists(input))
            {
                throw new InspectionInputException("The executable or installation folder does not exist: " + input);
            }

            string[] candidates =
            [
                Path.Combine(input, "Settlers7R.exe"),
                Path.Combine(input, "Bin", "Settlers7R.exe"),
                Path.Combine(input, "Base", "Bin", "Settlers7R.exe"),
                Path.Combine(input, "Data", "Base", "Bin", "Settlers7R.exe")
            ];
            string[] matches = candidates.Where(File.Exists).ToArray();
            if (matches.Length == 0)
            {
                throw new InspectionInputException("No Settlers7R.exe was found in this folder, Bin, Base/Bin or Data/Base/Bin. Supply the executable path explicitly.");
            }
            if (matches.Length > 1)
            {
                throw new InspectionInputException("More than one Settlers7R.exe was found. Supply the executable path explicitly: " + string.Join("; ", matches));
            }
            return matches[0];
        }

        private static BinaryInspection InspectBinary(string path)
        {
            // FileShare.Read prevents another writer from changing the bytes while
            // the fingerprint is calculated. Nothing is created beside the input.
            using FileStream input = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            string fingerprint = Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();
            FileVersionInfo version = FileVersionInfo.GetVersionInfo(path);
            return new BinaryInspection
            {
                Name = Path.GetFileName(path),
                Path = path,
                Size = input.Length,
                Sha256 = fingerprint,
                FileVersion = version.FileVersion,
                ProductVersion = version.ProductVersion
            };
        }

        private static bool IsRelevantDependency(string name)
        {
            if (!name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
            return name.StartsWith("uplay", StringComparison.OrdinalIgnoreCase)
                || name.Contains("ubiservices", StringComparison.OrdinalIgnoreCase)
                || name.Contains("quazal", StringComparison.OrdinalIgnoreCase)
                || name.Contains("rendezvous", StringComparison.OrdinalIgnoreCase)
                || name.Contains("network", StringComparison.OrdinalIgnoreCase);
        }

        private sealed class InspectionInputException(string message) : Exception(message) { }
    }

    internal sealed class InspectionReport
    {
        public int SchemaVersion { get; set; } = 1;
        public string Mode { get; set; } = "read-only-inspection";
        public string Status { get; set; } = "error";
        public int ExitCode { get; set; }
        public string Input { get; set; }
        public string Edition { get; set; }
        public bool RecognizedBuild { get; set; }
        public bool LanCompatibilityVerified { get; set; } = false;
        public BinaryInspection Executable { get; set; }
        public List<BinaryInspection> NetworkLibraries { get; set; } = [];
        public List<string> Notes { get; set; } = [];
        public string Error { get; set; }
    }

    internal sealed class BinaryInspection
    {
        public string Name { get; set; }
        public string Path { get; set; }
        public long Size { get; set; }
        public string Sha256 { get; set; }
        public string FileVersion { get; set; }
        public string ProductVersion { get; set; }
    }

    [JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
    [JsonSerializable(typeof(InspectionReport))]
    internal partial class InspectionJsonContext : JsonSerializerContext { }
}
