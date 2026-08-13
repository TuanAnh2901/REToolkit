"""Attach Frida to a running Everlusting Life process and record derank offsets."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from retoolkit.adapters.frida import FridaAdapter


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, help="explicit PID; omit to auto-select")
    ap.add_argument("--process", default="Everlusting Life",
                    help="process-name substring used when --pid is omitted")
    ap.add_argument("--duration", type=int, default=0,
                    help="milliseconds; 0 keeps probing until Ctrl+C")
    ap.add_argument("--out", type=Path, default=Path("Analysis2/frida/derank-field-probe.jsonl"))
    args = ap.parse_args()
    script = Path(__file__).resolve().parents[1] / "profiles" / "everlusting" / "frida" / "derank_field_probe.js"
    timeout = 3600 if args.duration <= 0 else max(120, args.duration // 1000 + 30)
    adapter = FridaAdapter(timeout_seconds=timeout)
    resolved_pid = args.pid if args.pid is not None else adapter.select_pid(args.process)
    print(f"[probe] attaching pid={resolved_pid}; Ctrl+C stops and saves the trace", flush=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    stream = args.out.open("w", encoding="utf-8", buffering=1)
    shown_hits: dict[str, int] = {}

    def show_event(entry: dict) -> None:
        stream.write(json.dumps(entry, sort_keys=True) + "\n")
        stream.flush()
        payload = entry.get("message", {}).get("payload")
        if payload == "__retoolkit_done__":
            print("[probe] sentinel received; detaching", flush=True)
            return
        if isinstance(payload, dict):
            kind = payload.get("kind", payload.get("type", "event"))
            body = payload.get("payload", {})
            if kind == "field":
                print(f"[field] {body.get('className')}::{body.get('fieldName')} offset={body.get('fieldOffset')}", flush=True)
            elif kind == "hit":
                key = f"{body.get('className')}::{body.get('methodName')}"
                shown_hits[key] = shown_hits.get(key, 0) + 1
                if shown_hits[key] <= 3 or shown_hits[key] % 25 == 0:
                    print(f"[hit {shown_hits[key]}] {key} self={body.get('self')} field={body.get('fieldValue')}", flush=True)
            elif kind in ("module", "error"):
                print(f"[{kind}] {body}", flush=True)
    try:
        messages = adapter.run_trace(target=resolved_pid, trace_script=script,
            params={"duration_ms": args.duration if args.duration > 0 else 3600000},
            mode="attach", on_message=show_event)
    finally:
        stream.close()
    print(json.dumps({"pid": resolved_pid, "out": str(args.out.resolve()), "messages": len(messages)}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
