/*
    Copyright (C) 2021 CodeStrikers.org
    This file is part of NETReactorSlayer.
    NETReactorSlayer is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    NETReactorSlayer is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with NETReactorSlayer.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using NETReactorSlayer.Core.Abstractions;
using NETReactorSlayer.Core.Helper;
using NETReactorSlayer.Core.Stages;

namespace NETReactorSlayer.Core
{
    public class Program
    {
        public static int Main(string[] args)
        {
            if (!CheckArguments(args))
                return 0;

            try
            {
                Console.Title = ".NET Reactor Slayer";
                Console.OutputEncoding = Encoding.UTF8;
                Console.BackgroundColor = ConsoleColor.Black;
                Console.ForegroundColor = ConsoleColor.White;
            }
            catch { }

            IOptions options = new Options(args);
            IContext context = new Context(options, new Logger(options.Verbose));

            try
            {
                Console.Clear();
                context.Logger.PrintLogo();
            }
            catch { }

            bool ok = false;
            if (context.Load())
            {
                DeobfuscateBegin(context);
                DeobfuscateEnd(context);
                ok = true;
            }

            if (!options.NoPause)
            {
                try
                {
                    Console.WriteLine("\r\n  Press any key to exit . . .");
                    if (!Console.IsInputRedirected)
                        Console.ReadKey();
                }
                catch { }
            }

            return ok ? 0 : 1;
        }

        private static bool CheckArguments(IReadOnlyList<string> args)
        {
            if (args.Count != 3 || args[0] != "--del-temp" ||
                !int.TryParse(args[1], out var id) || !File.Exists(args[2]))
                return true;

            try
            {
                if (Process.GetProcessById(id) is { } process)
                {
                    process.WaitForExit();
                    while (File.Exists(args[2]))
                    {
                        try { File.Delete(args[2]); }
                        catch { }

                        Thread.Sleep(1000);
                    }

                    Process.GetCurrentProcess().Kill();
                    return false;
                }
            }
            catch { }

            return true;
        }

        private static void DeobfuscateBegin(IContext context)
        {
            const int maxStackSize = 1024 * 1024 * 64;
            foreach (var deobfuscatorStage in context.Options.Stages)
            {
                var stageName = deobfuscatorStage.GetType().Name;
                context.Logger.Info($"Stage: {stageName}");
                var thread = new Thread(() =>
                {
                    try { deobfuscatorStage.Run(context); }
                    catch (Exception ex)
                    {
                        context.Logger.Error($"{stageName}: {ex.GetType().Name}: {ex.Message}");
                        if (context.Options.Verbose)
                            context.Logger.Error(ex.ToString());
                    }
                }, maxStackSize);
                thread.Start();
                thread.Join();
            }
        }

        private static void DeobfuscateEnd(IContext context)
        {
            if (context.Options.Stages.Any(x => x.GetType().Name.Equals(nameof(MethodInliner))))
                if (MethodInliner.InlinedMethods > 0)
                    context.Logger.Info(MethodInliner.InlinedMethods + " Methods inlined.");
                else
                    context.Logger.Warn("Couldn't find any outline method.");

            if (CodeVirtualizationUtils.Detect(context))
                context.Logger.Warn(
                    "WARNING: CODE VIRTUALIZATION HAS BEEN DETECTED, INCOMPLETE DEOBFUSCATION OF THE ASSEMBLY MAY RESULT.");

            context.Save();
        }
    }
}