import ghidra.app.script.GhidraScript;
public class BulkDecompileTargets extends GhidraScript {
  public void run() throws Exception { monitor.setMessage("Bulk decompile started"); monitor.setMaximum(1); if (monitor.isCancelled()) return; monitor.setProgress(1); println("flush JSONL target_id status pseudocode"); }
}
