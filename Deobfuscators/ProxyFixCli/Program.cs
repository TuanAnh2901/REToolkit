using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace ProxyFixCli;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length < 1 || args.Contains("-h") || args.Contains("--help"))
        {
            Console.WriteLine("Usage: ProxyFixCli <input.dll|input.exe> [output] [--remove-junk]");
            Console.WriteLine("  output defaults to <name>_noproxy<ext> next to input (same as GUI v2).");
            return 2;
        }

        var input = args[0];
        var removeJunk = args.Contains("--remove-junk");
        var output = args.Skip(1).FirstOrDefault(a => !a.StartsWith("-"));
        output ??= Path.Combine(Path.GetDirectoryName(input)!,
            $"{Path.GetFileNameWithoutExtension(input)}_noproxy{Path.GetExtension(input)}");

        if (!File.Exists(input))
        {
            Console.Error.WriteLine($"file not found: {input}");
            return 1;
        }

        ModuleDefMD module;
        try { module = ModuleDefMD.Load(input); }
        catch (BadImageFormatException) { Console.Error.WriteLine("not a .NET PE file."); return 1; }

        var (fixedCalls, removedJunk) = ProxyFixer.Fix(module, removeJunk);
        try { module.Write(output); }
        catch (ModuleWriterException)
        {
            var opts = new ModuleWriterOptions { Logger = DummyLogger.NoThrowInstance };
            module.Write(output, opts);
        }

        Console.WriteLine($"fixed={fixedCalls} removed-junk={removedJunk} output={output}");
        return 0;
    }
}

internal static class ProxyFixer
{
    public static (int fixedCalls, int removedJunk) Fix(ModuleDefMD module, bool removeJunk)
    {
        var junkMethods = new List<MethodDef>();
        var fixedCalls = 0;

        foreach (var type in module.GetTypes())
        {
            foreach (var method in type.Methods)
            {
                if (!method.HasBody)
                    continue;
                var instructions = method.Body.Instructions;
                for (var i = 0; i < instructions.Count; i++)
                {
                    if (!instructions[i].OpCode.Equals(OpCodes.Call))
                        continue;
                    try
                    {
                        if (instructions[i].Operand is not MethodDef { IsStatic: true } target || !type.Methods.Contains(target))
                            continue;
                        var realOperand = GetProxyTarget(target, out var realOp);
                        if (realOp == null || realOperand == null)
                            continue;
                        instructions[i].OpCode = realOp;
                        instructions[i].Operand = realOperand;
                        fixedCalls++;
                        if (!junkMethods.Contains(target))
                            junkMethods.Add(target);
                    }
                    catch { /* keep original instruction on any analysis failure */ }
                }
            }
        }

        var removed = 0;
        if (fixedCalls > 0 && removeJunk)
        {
            foreach (var type in module.GetTypes())
            {
                foreach (var junk in type.Methods.Where(junkMethods.Contains).ToList())
                {
                    type.Methods.Remove(junk);
                    removed++;
                }
            }
            junkMethods.Clear();
        }
        return (fixedCalls, removed);
    }

    private static object? GetProxyTarget(MethodDef proxy, out OpCode? realOp)
    {
        var body = proxy.Body.Instructions.ToArray();
        realOp = null;
        if (body.Length < 2)
            return null;
        var last = body.Length - 2;
        if (!body[last].OpCode.Equals(OpCodes.Newobj) && !body[last].OpCode.Equals(OpCodes.Call) && !body[last].OpCode.Equals(OpCodes.Callvirt))
            return null;
        if (body[last + 1].OpCode.Code != Code.Ret)
            return null;
        if (body.Length != proxy.Parameters.Count + 2)
            return null;
        realOp = body[last].OpCode;
        return body[last].Operand;
    }
}
