using de4dot.blocks;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UnConfuserEx.Protections.AntiDump
{
    internal class AntiDumpRemover : IProtection
    {
        public string Name => "AntiDump";

        int callIndex;
        MethodDef? antiDumpMethod;

        public bool IsPresent(ref ModuleDefMD module)
        {
            var cctor = module.GlobalType.FindStaticConstructor();

            if (cctor == null || !(cctor.HasBody) || cctor.Body.Instructions.Count == 0)
                return false;

            IList<Instruction> instrs;

            // Check the first calls in the constructor
            callIndex = 0;
            while (cctor.Body.Instructions[callIndex].OpCode == OpCodes.Call)
            {
                var method = cctor.Body.Instructions[callIndex].Operand as MethodDef;
                if (!method!.HasBody)
                {
                    callIndex++;
                    continue;
                }

                instrs = method!.Body.Instructions;
                if (instrs.Count > 6 &&
                    instrs[0].OpCode == OpCodes.Ldtoken &&
                    (TypeDef)instrs[0].Operand == module.GlobalType &&
                    instrs[5].OpCode == OpCodes.Call &&
                    ((IMethodDefOrRef)instrs[5].Operand).MethodSig.ToString() == "System.IntPtr (System.Reflection.Module)")
                {
                    antiDumpMethod = method;
                    return true;
                }
                callIndex++;
            }
            callIndex = -1;


            // Then check the body itself
            instrs = cctor.Body.Instructions;
            if (instrs.Count > 6 &&
                instrs[0].OpCode == OpCodes.Ldtoken &&
                (TypeDef)instrs[0].Operand == module.GlobalType &&
                instrs[5].OpCode == OpCodes.Call &&
                ((IMethodDefOrRef)instrs[5].Operand).Name == "GetHINSTANCE")
            {
                antiDumpMethod = cctor;
                return true;
            }

            return false;
        }

        public bool Remove(ref ModuleDefMD module)
        {
            var cctor = module.GlobalType.FindStaticConstructor();

            if (antiDumpMethod == cctor)
            {
                // TODO: This will cause issues if any protections were injected afterwards...
                cctor.Body.Instructions.Clear();
                cctor.Body.Instructions.Add(Instruction.Create(OpCodes.Ret));
            }
            else
            {
                cctor.Body.Instructions.RemoveAt(callIndex);
                module.GlobalType.Methods.Remove(antiDumpMethod);
            }

            return true;
        }
    }
}
