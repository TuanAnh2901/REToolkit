# ProxyFixCli

CLI port of **ConfuserEx Proxy Call Fixer v2** (DaviCore, WinForms GUI-only) for batch deobfuscation pipelines. Same algorithm, no GUI.

## What it does

Scans every method body for `call` instructions targeting a same-type static proxy whose body matches the ConfuserEx proxy pattern (final real instruction is `newobj`/`call`/`callvirt` + `ret`, body length = param count + 2). Replaces the call site with the real opcode + operand, collects the proxies as junk, and optionally deletes them (`--remove-junk`).

## Usage

```
dotnet run --project Deobfuscators/ProxyFixCli -- <input.dll|input.exe> [output] [--remove-junk]
```

- `output` defaults to `<name>_noproxy<ext>` next to the input (same convention as the GUI).
- Prints `fixed=N removed-junk=M output=...`, exit 0 on success.

## Pipeline position

```
UnConfuserEx.exe <in> <deob>          # unpack + anti-tamper/cflow/constants/resources
ProxyFixCli <deob> <noproxy> --remove-junk
ilspycmd -p -o <proj> <noproxy>       # compilable project
```

Verified: 91 proxy calls fixed + 60 junk methods removed on a real ConfuserEx mod DLL; 229 + 147 on another.

## Build

Requires .NET 9 SDK. `dnlib.dll` (local copy, same folder) is the only dependency — no NuGet needed.
