// Derived from Everlusting Life Analysis/GhidraScripts/DecompileTargets.java
// (original written for the Everlusting Life RE workspace). Semantics preserved:
// each script arg is a full virtual address in the default address space
// (hex string, no 0x prefix); the function at that address is decompiled and
// printed to the console with a TARGET marker.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class DecompileTargets extends GhidraScript {
    @Override
    protected void run() throws Exception {
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try {
            for (String argument : getScriptArgs()) {
                println("TARGET " + argument);
                Address address = currentProgram.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(argument);
                ghidra.program.model.listing.Function function =
                        getFunctionAt(address);
                if (function == null) {
                    function = getFunctionContaining(address);
                }
                if (function == null) {
                    println("FUNCTION_NOT_FOUND");
                    continue;
                }
                println("FUNCTION " + function.getName() + " @ " + function.getEntryPoint());
                DecompileResults results = decompiler.decompileFunction(function, 180, monitor);
                if (results != null && results.decompileCompleted()) {
                    println(results.getDecompiledFunction().getC());
                } else {
                    println("DECOMPILATION_FAILED " + (results == null
                            ? "null results" : results.getErrorMessage()));
                }
            }
        } finally {
            decompiler.dispose();
        }
    }
}
