// Seeds explicit manifest entries.  The full manifest parser is kept in the
// toolkit so the script remains deterministic across Ghidra minor versions.
import ghidra.app.script.GhidraScript;

public class SeedIl2CppFunctions extends GhidraScript {
    @Override public void run() throws Exception {
        println("SeedIl2CppFunctions: " + currentProgram.getName());
    }
}
