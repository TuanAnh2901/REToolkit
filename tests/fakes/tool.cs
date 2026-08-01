// FakeTool.exe: scriptable fake external tool for adapter tests.
// Behavior comes from a text file at %FAKETOOL_BEHAVIOR%, one directive per line:
//   exit=N              process exit code (default 0)
//   sleep_ms=N          sleep before exiting
//   stdout=<text>       write text to stdout
//   stderr=<text>       write text to stderr
//   spawn_child         start a detached child process (cmd /c ping ...) before sleeping
//   write_file|<dir>|<name>|<content>
// Always writes its argv as JSON into fake-argv.json in the current directory.
// Compile: Add-Type -TypeDefinition (Get-Content -Raw tool.cs) -OutputAssembly faketool.exe
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

class Program
{
    static int Main(string[] args)
    {
        File.WriteAllText(Path.Combine(Environment.CurrentDirectory, "fake-argv.json"),
            "[" + string.Join(",", args.Select(a => "\"" + a.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"")) + "]");
        File.WriteAllText(Path.Combine(Environment.CurrentDirectory, "fake-pids.json"),
            "{\"own\":" + Process.GetCurrentProcess().Id + "}");

        string capturePath = Environment.GetEnvironmentVariable("FAKETOOL_CAPTURE");
        if (!string.IsNullOrEmpty(capturePath))
        {
            string encoded = "[" + string.Join(",", args.Select(a => "\"" + a.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"")) + "]\n";
            File.AppendAllText(capturePath, encoded);
        }

        string behaviorPath = Environment.GetEnvironmentVariable("FAKETOOL_BEHAVIOR");
        if (string.IsNullOrEmpty(behaviorPath))
        {
            Console.Error.WriteLine("FAKETOOL_BEHAVIOR not set");
            return 5;
        }

        int exit = 0;
        int sleepMs = 0;
        foreach (string line in File.ReadAllLines(behaviorPath))
        {
            if (line.StartsWith("exit=")) { int.TryParse(line.Substring(5), out exit); }
            else if (line.StartsWith("sleep_ms=")) { int.TryParse(line.Substring(9), out sleepMs); }
            else if (line == "spawn_child")
            {
                Process child = Process.Start(new ProcessStartInfo("cmd.exe", "/c ping -n 60 127.0.0.1 >nul")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                });
                string pidsPath = Path.Combine(Environment.CurrentDirectory, "fake-pids.json");
                File.WriteAllText(pidsPath, "{\"own\":" + Process.GetCurrentProcess().Id + ",\"child\":" + child.Id + "}");
            }
            else if (line.StartsWith("stdout=")) { Console.Out.Write(line.Substring(7)); }
            else if (line.StartsWith("stderr=")) { Console.Error.Write(line.Substring(7)); }
            else if (line.StartsWith("append_line|"))
            {
                string[] parts = line.Substring(12).Split('|');
                string dir = parts[0];
                string name = parts[1];
                string text = line.Substring(12 + dir.Length + 1 + name.Length + 1);
                Directory.CreateDirectory(dir);
                File.AppendAllText(Path.Combine(dir, name), text + "\r\n");
            }
            else if (line.StartsWith("write_file|"))
            {
                string[] parts = line.Substring(11).Split('|');
                string dir = parts[0];
                string name = parts[1];
                string content = line.Substring(11 + dir.Length + 1 + name.Length + 1);
                Directory.CreateDirectory(dir);
                File.WriteAllText(Path.Combine(dir, name), content);
            }
        }

        if (sleepMs > 0) System.Threading.Thread.Sleep(sleepMs);
        return exit;
    }
}
