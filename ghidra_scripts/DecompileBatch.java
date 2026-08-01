// Single-process batch entry point.  The runner records durable per-target
// results and progress; this script is intentionally side-effect bounded.
import ghidra.app.script.GhidraScript;

public class DecompileBatch extends GhidraScript {
    @Override public void run() throws Exception {
        println("DecompileBatch: " + currentProgram.getName());
    }
}
