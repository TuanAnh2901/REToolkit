using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MSILEmulator.Instructions.Branch
{
    internal class Bne
    {
        public static int Emulate(Context ctx, Instruction instr)
        {
            object val2 = ctx.Stack.Pop();
            object val1 = ctx.Stack.Pop();

            if (val1.GetType() != val2.GetType())
            {
                throw new EmulatorException($"Attempted to compare different types {val1.GetType()} != {val2.GetType()}");
            }

            // Must be a better way of doing this?

            if (val1.GetType() == typeof(int))
            {
                if ((int)val1 != (int)val2)
                {
                    return ctx.Offsets[((Instruction)instr.Operand).Offset];
                }
                else
                {
                    return ctx.Offsets[instr.Offset] + 1;
                }
            }

            if (val1.GetType() == typeof(long))
            {
                if ((long)val1 != (long)val2)
                {
                    return ctx.Offsets[((Instruction)instr.Operand).Offset];
                }
                else
                {
                    return ctx.Offsets[instr.Offset] + 1;
                }
            }

            throw new NotImplementedException($"Comparison of {val1.GetType().Name} not handled");
        }
    }
}
