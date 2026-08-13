"""Read-only Frida probe for one Multichest Open All interaction."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from retoolkit.adapters.frida import FridaAdapter

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int)
    ap.add_argument("--process", default="Everlusting Life")
    ap.add_argument("--duration", type=int, default=120000)
    ap.add_argument("--out", type=Path, default=Path("Analysis2/frida/multichest-open-probe.jsonl"))
    args = ap.parse_args()
    script = Path(__file__).resolve().parents[1] / "profiles" / "everlusting" / "frida" / "multichest_open_probe.js"
    adapter = FridaAdapter(timeout_seconds=max(120, args.duration // 1000 + 30))
    pid = args.pid if args.pid is not None else adapter.select_pid(args.process)
    print(f"[probe] attaching pid={pid}; open one Multi Reward and press Open All; Ctrl+C stops", flush=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    stream = args.out.open("w", encoding="utf-8", buffering=1)
    def show(entry: dict) -> None:
        stream.write(json.dumps(entry, sort_keys=True) + "\n"); stream.flush()
        payload = entry.get("message", {}).get("payload")
        if isinstance(payload, dict):
            kind, body = payload.get("kind"), payload.get("payload", {})
            if kind in ("module", "method", "field", "window_fields", "button_click", "error", "attach_error"):
                print(f"[{kind}] {body}", flush=True)
    try:
        adapter.run_trace(target=pid, trace_script=script, params={"duration_ms": args.duration}, mode="attach", on_message=show)
    except KeyboardInterrupt:
        print("[probe] stopped by Ctrl+C", flush=True)
    finally:
        stream.close()
    print(f"[probe] output={args.out.resolve()}", flush=True)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
