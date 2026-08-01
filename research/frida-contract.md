# Frida Runner Contract (probed 2026-07-31)

## Environment

| Item | Value |
|---|---|
| Frida Python bindings | `17.16.3` (verified `py -3.13 -c "import frida"`) |
| Python | 3.13 only. Frida is **not** installed for system Python (3.12). |
| JS runtime | ES5 / Duktape. No `import`/`export`, no modules. Flat functions. |
| Runner | `src/retoolkit/adapters/frida_runner.py` (generic, test-injectable) |
| Adapter | `src/retoolkit/adapters/frida.py` (`FridaAdapter`, owns profile + evidence path) |
| Preamble | `src/retoolkit/runtime/resolver.js` (IL2CPP resolver, prepended to every script) |
| Tests | `tests/test_frida_runner.py` (fake device/session/script, no live process) |
| Live test | `tests/live/test_frida_live.py` (gated) |
| Pattern source | `D:\SteamLibrary\steamapps\common\Everlusting Life\Analysis\run_frida_metadata_loader_trace.py` |

## Modes: spawn vs attach

`FridaRunConfig.mode` selects the lifecycle. Both paths collect messages
through the same `on_message` handler.

- **attach** (`mode="attach"`): `device.attach(pid)`. Target is an int PID.
  Script loads, no resume call. Cleanup = `session.detach()` only; the
  attached process is never killed.
- **spawn** (`mode="spawn"`): `device.spawn(name)` then
  `device.attach(spawned_pid)`. Target is a process name/path. Script loads
  *before* `device.resume(pid)` so the preamble and hooks are in place at
  first instruction. Cleanup = detach **plus** `device.kill(pid)`.

Device selection: `get_usb_device_id()` when the binding exposes it,
otherwise `get_device(None)` (local device). The EL pattern source uses
`get_local_device()` directly.

## Script loading

1. Params are JSON-encoded with `sort_keys=True` and prepended to the source:
   `globalThis.__RETOOLKIT_PARAMS = {...};\n` then the user script. No RPC
   round-trip; the script reads params from the global at load time.
2. `session.create_script(source)`, `script.on("message", on_message)`,
   `script.load()`.
3. In spawn mode `device.resume(pid)` runs only after `load()` returns.
4. The full source (preamble + script) is one file passed to
   `create_script`; there is no runtime file I/O inside Frida.

## Message format (JSONL)

`on_message(message, data)` receives the raw frida message dict. The runner
wraps each delivery as `{"message": {...}, "data": "..."?}`:

- `message` = the frida message object. `{"type": "send", "payload": ...}`
  is the JSONL-relevant shape; `type: "error"`/`"log"` messages pass through
  unchanged.
- `data` = optional binary buffer (e.g. a dumped metadata region). Decoded
  `utf-8` with `errors="replace"` when present, else `str(data)`.
- The adapter persists each entry as one JSON line (`.jsonl`), matching the
  EL pattern (`json.dumps(message) + "\n"` per event, flushed per line).
- Order is preserved; the collection is append-only.

## Sentinel completion

- Default sentinel: `"__retoolkit_done__"`, overridable in
  `FridaRunConfig.sentinel`.
- Detection: the sentinel string appears as the top-level `payload` string,
  or as any **value** of a payload dict (`_sentinel_markers`). It does not
  match payload keys.
- On match: `sentinel_seen = True`, the completion `threading.Event` is set,
  `run()` returns `FridaRunResult(messages, sentinel_seen=True)`.
- Scripts are expected to `send("__retoolkit_done__")` (or
  `send({event: "__retoolkit_done__"})`) as their final message.

## Timeout and cleanup

- `completed.wait(config.timeout_seconds)`. Default 30 s; live adapter runs
  use 180 s.
- Sentinel not seen within budget: `ResultError.timeout(...)` raised,
  exit code **3** (`ExitCode.TIMEOUT`), message names the sentinel and
  budget.
- Cleanup is unconditional (`finally`), both on success and timeout:
  - `session.detach()`, exceptions swallowed.
  - spawn mode only: `device.kill(spawned_pid)`, exceptions swallowed.
- Contract after `run()` returns or raises: no attached session and no
  spawned child remains. Verified by tests
  (`session.detached`, `device.killed == [pid]`).

## IL2CPP resolver preamble (resolver.js)

`FridaAdapter.run_trace` prepends `resolver.js` to the trace script. It is a
resolve-only behavioral reimplementation of the `battle_cheat
il2cpp_resolve.js` API: no `Interceptor` hooks, no memory writes.

Exposed API (`global.retoolkitResolver`, every method guarded and errors
reported as `{type: "resolver", kind: "error", ...}` sends):

| Method | Contract |
|---|---|
| `waitForIl2Cpp()` | Polls `Process.findModuleByName("GameAssembly.dll")` (up to `ga_timeout_ms`, default 30000), then probes `il2cpp_domain_get` + `Assembly-CSharp` image with `class_count > 0` (up to `il2cpp_timeout_ms`, default 30000). Throws if not ready. |
| `getClass(full)` | Namespace + assembly-aware. `full` = `[Assembly::]Ns.ClassName`. Class name collision-safe: candidates kept per name as a list, filtered by ns then by assembly. |
| `getMethodInfo(cls, method, paramCount)` | Walks class + inherited parents (`il2cpp_class_get_parent`); `paramCount < 0` matches any arity. |
| `resolveMethodPointer(cls, method, paramCount)` | Cached. Sends `{type: "resolver", kind: "ok"|"not_found", payload: {target, pointer/address, reason}}`. Pointer = `MethodInfo + method_info_code_offset` (default 0x08) `readPointer()`. |
| `getField` / `resolveStaticFieldAddress` | Field lookup incl. inherited; static detection via `FIELD_ATTRIBUTE_STATIC` (0x0010). Static address = `il2cpp_class_get_static_fields(klass) + field_offset`. |
| `resolveIcall(name)` | `il2cpp_resolve_icall` wrapper. |

Params consumed by the preamble: `ga_timeout_ms`, `il2cpp_timeout_ms`,
`method_info_code_offset`, `assemblies` (default `Assembly-CSharp`,
`UnityEngine.CoreModule`, `mscorlib`, `System`, `System.Core`).

## Live gate

- `RETOOLKIT_LIVE_FRIDA=1` plus `RETOOLKIT_GAME_ROOT` must both be set for
  `tests/live/test_frida_live.py`; otherwise the test skips with a reason.
  Documented in `README.md`: spawn the game and run a resolve-only trace.
- Live contract: spawn `Everlusting Life.exe` under `RETOOLKIT_GAME_ROOT`,
  run the resolver + `init-trace.js`, assert the JSONL contains resolver or
  trace messages, detach, kill child. Never attaches to non-profile targets;
  never leaves the spawned child running.
- Live attach testing against Everlusting Life requires the game actually
  running and the live gate enabled; offline/fake-device tests do not cover
  real timing.

## Evidence path

The adapter writes the collected entries as JSONL (one message wrapper per
line) into the toolkit workspace, which is then hashed into evidence.
Convention (inherited from EL `Analysis/`): `.jsonl` traces are
machine-generated evidence and are never edited by hand.
