# Profile authoring

A profile is the only thing you touch to add a new game or metadata fixup —
core code never changes.

## Minimal profile

```json
{
  "schema_version": "1.0.0",
  "name": "my-game",
  "game": {
    "root": "${RETOOLKIT_GAME_ROOT}",
    "game_assembly": "${RETOOLKIT_GAME_ROOT}/GameAssembly.dll",
    "metadata": "${RETOOLKIT_GAME_ROOT}/Data/global-metadata.dat"
  },
  "workspace": "${RETOOLKIT_WORKSPACE}",
  "tools": {
    "cpp2il": { "path": "${RETOOLKIT_CPP2IL}",
                "plugin_dir": "${RETOOLKIT_CPP2IL_PLUGINS}",
                "timeout_seconds": 600 }
  },
  "stages": { "fixup": false, "cpp2il": true, "frida": false, "ghidra": false }
}
```

Path rules:

- No absolute paths in committed profiles. Use `${ENV_VAR}` templates
  (resolved at runtime) or relative paths (resolved against the profile
  directory, must not escape it).
- `py -3.13 -m retoolkit profile validate <profile> --fixture` checks
  portability (no committed literals).

## Adding a metadata fixup

If the game's metadata starts with a custom magic (e.g. `e1b06cfe` for
Mfuscator), add a `metadata_fixup` object validated against
`schemas/metadata_fixup.schema.json`:

1. Decrypt the custom header and determine: header offset/length, payload
   start, preserved-tail start, source bias, mutations, and the section field
   map (`custom_offset_field` / `custom_size_field` per section).
2. Record payload transforms (`initial`, `step`) for XOR-encoded sections.
3. Compute `known_good_hash` from a rebuild that a real Cpp2IL successfully
   loads (the fixup stage reports `matches_known_good`).
4. Copy the object into `metadata_fixup` and keep the canonical copy under
   `tests/fixtures/<game>/fixup-config.json` (the acceptance suite verifies
   they stay in sync).

Everything the fixup needs lives in this object — no core source changes.
`tests/test_mfuscator.py` shows the synthetic round-trip pattern for
validating your config without the real game file.

## Validation failures

Missing required field or unknown property -> `profile validate` exits 1 with
field-level errors:

```json
{ "error": { "code": "validation",
  "details": ["game: 'game_assembly' is a required property"] } }
```

Unset environment variable -> exit 1 naming the variable. Absolute path in a
committed profile (fixture mode) -> exit 1 naming the field. Fix the field,
not the validator.

## Stage notes

- `fixup` runs only when `metadata_fixup` exists and the stage is enabled.
- `normalize` follows `cpp2il`; set `method_map_collision_policy` to
  `"keep_all"` when the map has generic-instantiation signature collisions
  (report is the default and will fail loudly).
- `frida` / `ghidra` are optional: a disabled stage or a missing optional
  capability produces a documented skip, never an internal error.
- `analysis.ghidra_targets` (RVA integers) and `analysis.image_base`
  (default `0x180000000`) drive the optional Ghidra stage.
