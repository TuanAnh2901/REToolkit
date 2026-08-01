# retoolkitResolver API

`src/retoolkit/runtime/resolver.js` is a resolve-only IL2CPP resolver for
Frida scripts (ES5 / Duktape). It exposes `global.retoolkitResolver` after
injection. It never attaches hooks and never writes memory.

## Configuration

Read from `globalThis.__RETOOLKIT_PARAMS` (the Frida runner prepends this):

| Key | Default | Meaning |
|---|---|---|
| `assemblies` | `["Assembly-CSharp", "UnityEngine.CoreModule", "mscorlib", "System", "System.Core"]` | assemblies indexed into the class map |
| `ga_timeout_ms` | `30000` | max wait for `GameAssembly.dll` module |
| `il2cpp_timeout_ms` | `30000` | max wait for the IL2CPP runtime to be ready |
| `method_info_code_offset` | `0x08` | native code pointer offset inside `MethodInfo` |

## Functions

All return `null` (and emit a structured message) on failure; never throw.

| Function | Returns |
|---|---|
| `waitForIl2Cpp()` | `undefined`; waits until the runtime is ready |
| `getClass(className)` | class pointer for `"Namespace.Class"` or `"Assembly::Namespace.Class"` |
| `getMethodInfo(className, methodName, paramCount)` | `MethodInfo` pointer; `paramCount < 0` = wildcard |
| `resolveMethodPointer(className, methodName, paramCount)` | native code pointer (memoized) |
| `getField(className, fieldName)` | `{ offset, isStatic, klass }` (inherited fields included) |
| `resolveStaticFieldAddress(className, fieldName)` | absolute static field address (memoized) |
| `resolveIcall(name)` | icall address, e.g. `"UnityEngine.Time::set_timeScale"` |

## Messages

Each call emits one structured `send()` message:

```json
{ "type": "resolver", "kind": "ok" | "not_found" | "error",
  "payload": { "target": "...", "pointer": "0x...", "message": "..." } }
```

## Collision semantics

The class map keys short class names to arrays of `{ klass, ns, asm }`
candidates. `getClass` filters by namespace and assembly when the requested
name carries them; with no qualifier it returns the first candidate in
assembly order (deterministic, never last-wins).
