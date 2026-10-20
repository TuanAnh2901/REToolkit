"""Deep probe: MultichestWindow elements list + button bindings."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from retoolkit.adapters.frida import FridaAdapter

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int)
    ap.add_argument("--process", default="Everlusting Life")
    ap.add_argument("--duration", type=int, default=120000)
    ap.add_argument("--out", type=Path, default=Path("Analysis2/frida/multichest-deep-probe.jsonl"))
    args = ap.parse_args()
    script = Path(__file__).resolve().parents[1] / "profiles" / "everlusting" / "frida" / "multichest_deep_probe.js"
    adapter = FridaAdapter(timeout_seconds=max(120, args.duration // 1000 + 30))
    pid = args.pid if args.pid is not None else adapter.select_pid(args.process)
    print(f"[probe] attaching pid={pid}; open one Multi Reward; Ctrl+C stops", flush=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    stream = args.out.open("w", encoding="utf-8", buffering=1)
    def show(entry: dict) -> None:
        stream.write(json.dumps(entry, sort_keys=True) + "\n"); stream.flush()
        payload = entry.get("message", {}).get("payload")
        if isinstance(payload, dict):
            kind, body = payload.get("kind"), payload.get("payload", {})
            if kind in ("fields", "method", "enter", "error", "attach_error"):
                if kind == "fields":
                    d = body.get("data", {})
                    print(f"[fields:{body.get('methodName')}] self={d.get('self')} counts={d.get('counts')} flags={d.get('flags')}", flush=True)
                    if d.get("elements"):
                        el = d["elements"]
                        print(f"  elements: size={el.get('size')} list={el.get('list')}", flush=True)
                        for it in el.get("items", [])[:8]:
                            print(f"    [{it.get('index')}] ptr={it.get('ptr')} onClick={it.get('onClick')} onDown={it.get('onDown')}", flush=True)
                    if d.get("openCardsButton"):
                        ob = d["openCardsButton"]
                        print(f"  openCardsButton: {ob}", flush=True)
                    if d.get("closeButton"):
                        cb = d["closeButton"]
                        print(f"  closeButton: {cb}", flush=True)
                else:
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
