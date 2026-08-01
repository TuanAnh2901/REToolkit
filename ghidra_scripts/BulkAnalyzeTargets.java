import ghidra.app.script.GhidraScript;
public class BulkAnalyzeTargets extends GhidraScript {
  public void run() throws Exception { monitor.setMessage("Bulk analysis started"); monitor.setProgress(0); println("progress.json"); }
}
