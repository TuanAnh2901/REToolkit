"""Read-only Frida probe for the Auto Rank battle/reward flow."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from retoolkit.adapters.frida import FridaAdapter

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int)
    ap.add_argument("--process", default="Everlusting Life")
    ap.add_argument("--duration", type=int, default=120000)
    ap.add_argument("--out", type=Path, default=Path("Analysis2/frida/auto-rank-probe.jsonl"))
    args = ap.parse_args()
    script = Path(__file__).resolve().parents[1] / "profiles" / "everlusting" / "frida" / "auto_rank_probe.js"
    adapter = FridaAdapter(timeout_seconds=max(120, args.duration // 1000 + 30))
    pid = args.pid if args.pid is not None else adapter.select_pid(args.process)
    print(f"[probe] attaching pid={pid}; perform one Auto Rank battle; Ctrl+C stops", flush=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    stream = args.out.open("w", encoding="utf-8", buffering=1)
    counts = {}
    def show(entry: dict) -> None:
        stream.write(json.dumps(entry, sort_keys=True) + "\n"); stream.flush()
        p = entry.get("message", {}).get("payload")
        if isinstance(p, dict):
            k, body = p.get("kind"), p.get("payload", {})
            if k in ("module", "method", "field", "error"):
                print(f"[{k}] {body}", flush=True)
            elif k in ("hit", "return"):
                key = f"{body.get('className')}::{body.get('methodName')}"
                counts[key] = counts.get(key, 0) + 1
                if counts[key] <= 5 or counts[key] % 25 == 0:
                    print(f"[{k} {counts[key]}] {body}", flush=True)
            elif k == "object_scan":
                print(f"[scan] {body.get('className')} fields={body.get('fields')}", flush=True)
    try:
        adapter.run_trace(target=pid, trace_script=script, params={"duration_ms": args.duration}, mode="attach", on_message=show)
    except KeyboardInterrupt:
        print("[probe] stopped by Ctrl+C", flush=True)
    finally:
        stream.close()
    print(f"[probe] output={args.out.resolve()}", flush=True)
    return 0
if __name__ == "__main__": raise SystemExit(main())
