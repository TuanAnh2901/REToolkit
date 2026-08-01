// Imports a prepared PE/metadata pair without enabling broad auto-analysis.
// The Python runner owns cache publication; this script only reports the
// current program and exits non-zero through Ghidra's normal error path.
import ghidra.app.script.GhidraScript;

public class ImportPreparedProgram extends GhidraScript {
    @Override public void run() throws Exception {
        println("ImportPreparedProgram: " + currentProgram.getName());
    }
}
