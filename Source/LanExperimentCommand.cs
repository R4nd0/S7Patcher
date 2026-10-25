using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace S7Patcher.Source
{
    internal static class LanExperimentCommand
    {
        internal static bool TryRun(string[] args, out int exitCode)
        {
            exitCode = 0;
            if (!args.Any(value => value.StartsWith("--lan-experiment", StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }
            if (args.Length != 5 || args[0] != "--lan-experiment" || args[1] != "prepare" || args[3] != "--output")
            {
                Console.Error.WriteLine("Usage: S7Patcher --lan-experiment prepare <installation folder> --output <NEW staging directory>");
                exitCode = 2;
                return true;
            }

            string script = Path.Combine(AppContext.BaseDirectory, "tools", "lan", "prepare.py");
            if (!File.Exists(script))
            {
                Console.Error.WriteLine("LAN preparation tool is missing: " + script);
                exitCode = 1;
                return true;
            }
            foreach (string interpreter in OperatingSystem.IsWindows() ? new[] { "py", "python" } : new[] { "python3", "python" })
            {
                if (!IsCompatibleInterpreter(interpreter)) continue;
                ProcessStartInfo start = new(interpreter)
                {
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true
                };
                if (interpreter == "py") start.ArgumentList.Add("-3");
                start.ArgumentList.Add("-B");
                start.ArgumentList.Add(script);
                start.ArgumentList.Add(args[2]);
                start.ArgumentList.Add("--output");
                start.ArgumentList.Add(args[4]);
                Process process;
                try
                {
                    process = Process.Start(start);
                }
                catch (Win32Exception)
                {
                    continue;
                }
                if (process == null) continue;
                using (process)
                {
                    var stdout = process.StandardOutput.ReadToEndAsync();
                    var stderr = process.StandardError.ReadToEndAsync();
                    process.WaitForExit();
                    Console.Write(stdout.GetAwaiter().GetResult());
                    Console.Error.Write(stderr.GetAwaiter().GetResult());
                    exitCode = process.ExitCode;
                }
                return true;
            }
            Console.Error.WriteLine("Python 3.10 or newer is required for the local archive preparation tool. No game files were modified.");
            exitCode = 1;
            return true;
        }

        private static bool IsCompatibleInterpreter(string interpreter)
        {
            ProcessStartInfo probe = new(interpreter)
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            if (interpreter == "py") probe.ArgumentList.Add("-3");
            probe.ArgumentList.Add("-B");
            probe.ArgumentList.Add("-c");
            probe.ArgumentList.Add("import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)");
            try
            {
                using Process process = Process.Start(probe);
                if (process == null) return false;
                var stdout = process.StandardOutput.ReadToEndAsync();
                var stderr = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit(5000))
                {
                    process.Kill();
                    return false;
                }
                return process.ExitCode == 0;
            }
            catch (Win32Exception) { return false; }
            catch (InvalidOperationException) { return false; }
        }
    }
}
