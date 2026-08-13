using dnlib.DotNet;
using dnlib.DotNet.Emit;
using log4net;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace UnConfuserEx
{
    internal class Utils
    {
        private static ILog Logger = LogManager.GetLogger("Utils");

        public static byte[] DecompressLZMA(byte[] data, MethodDef initMethod)
        {
            int sizeBytes = GetUncompressedSizeBytes(initMethod);

            MemoryStream inStream = new MemoryStream(data);
            MemoryStream outStream = new MemoryStream();
            var decoder = new SevenZip.Compression.LZMA.Decoder();

            var props = new byte[5];
            if (inStream.Read(props, 0, 5) != 5)
            {
                throw new Exception("Failed to read LZMA properties");
            }
            Logger.Debug($"LZMA properties => {props[0]:X} {props[1]:X} {props[2]:X} {props[3]:X} {props[4]:X}");
            decoder.SetDecoderProperties(props);

            var size = new byte[8];
            if (inStream.Read(size, 0, sizeBytes) != sizeBytes)
            {
                throw new Exception("Failed to read uncompressed size");
            }
            long uncompressedSize = BitConverter.ToInt64(size);
            long compressedSize = inStream.Length - inStream.Position;

            Logger.Debug($"Compressed bytes: 0x{compressedSize:X} -> Uncompressed bytes: 0x{uncompressedSize:X}");
            
            decoder.Code(inStream, outStream, compressedSize, uncompressedSize, null);
            return outStream.ToArray();
        }

        private static int GetUncompressedSizeBytes(MethodDef initMethod)
        {
            // Iterate through all instructions to find the call to the decompress method
            foreach (var instr in initMethod.Body.Instructions)
            {
                if (instr.OpCode != OpCodes.Call || instr.Operand is not MethodDef callee)
                {
                    continue;
                }

                if (callee.Signature.ToString() != "System.Byte[] (System.Byte[])")
                {
                    continue;
                }

                // Attempt to find the number of bytes representing the uncompressed size
                var instrs = callee.Body.Instructions;
                for (int i = 0; i < instrs.Count - 1; i++)
                {
                    if (instrs[i].IsLdcI4() && instrs[i+1].OpCode == OpCodes.Blt_S && instrs[i].GetLdcI4Value() != 5)
                    {
                        Logger.Debug($"Using {instrs[i].GetLdcI4Value()} bytes for the uncompressed size");
                        return instrs[i].GetLdcI4Value();
                    }
                }

            }
            Logger.Warn("Failed to find number of bytes used by the uncompressed size. Defaulting to 4");
            return 4;
        }

        private static char[] InvalidChars = "!@#$%^&*()-=+\\,<>".ToArray();

        public static bool IsInvalidName(string name)
        {
            return Encoding.UTF8.GetByteCount(name) != name.Length
                    || (name.Any(c => InvalidChars.Contains(c)));
        }

        public static int GetStoreLocalIndex(Instruction instr)
        {
            if (instr.OpCode == OpCodes.Stloc_S || instr.OpCode == OpCodes.Stloc)
            {
                return ((Local)instr.Operand).Index;
            }
            else
            {
                return instr.OpCode.Code - Code.Stloc_0;
            }
        }

        public static int GetLoadLocalIndex(Instruction instr)
        {
            if (instr.OpCode == OpCodes.Ldloc_S || instr.OpCode == OpCodes.Ldloc)
            {
                return ((Local)instr.Operand).Index;
            }
            else
            {
                return instr.OpCode.Code - Code.Ldloc_0;
            }
        }
    }
}
