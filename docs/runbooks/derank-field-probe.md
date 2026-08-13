# Derank field probe

1. Start the game and reach the PvP battle screen. Do not enable EL Native
   derank automation during the probe.
2. Find the game PID:

   ```powershell
   Get-Process | Where-Object ProcessName -match 'Everlusting' | Select Id,Path
   ```

3. From `D:\VSCode\REToolkit`, run:

   ```powershell
   $env:PYTHONPATH='src'
   py -3.13 scripts\probe_derank_fields.py
   ```

   The script automatically finds the unique `Everlusting Life` process. Press
   `Ctrl+C` after collecting the events; the current JSONL is saved before the
   Frida session detaches. Use `--pid <PID>` only when multiple matching
   processes exist.

4. While it runs, open Battlefield settings, open the surrender confirmation,
   and click the left/confirm button once. The output is
   `Analysis2\frida\derank-field-probe.jsonl`.
5. Extract exact offsets:

   ```powershell
   Get-Content Analysis2\frida\derank-field-probe.jsonl |
     ConvertFrom-Json | ForEach-Object {$_.message.payload} |
     Where-Object {$_.kind -eq 'field' -or $_.kind -eq 'hit'}
   ```

`fieldOffset` is the IL2CPP instance-field offset to use in EL Native;
`self` and `fieldValue` prove that the object was live at the hooked method.
The probe is attach-only and detaches without killing the game.
