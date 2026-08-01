# REToolkit RE Index and Query Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Import the normalized Cpp2IL method map into a deterministic SQLite index and resolve exact, wildcard, and RVA target queries without starting Ghidra or Frida.

**Architecture:** Add a focused `retoolkit.re_index` package containing typed records, an idempotent SQLite store, a streaming importer, and a query service. Register `index build`, `index stats`, `target resolve`, and `target search` commands while preserving the existing JSON CLI envelope and profile path rules.

**Tech Stack:** Python 3.13 standard-library `sqlite3`, dataclasses, JSON Schema, pytest, existing Cpp2IL/normalizer/evidence contracts.

## Global Constraints

- Existing `Analysis` is read-only; database and reports use `Profile.workspace`, configured below `Analysis2` for the current profile.
- SQLite schema version starts at `1`; migrations are ordered, transactional, and idempotent.
- Preserve duplicate managed identities with different RVAs; never silently overwrite Cpp2IL generic-instantiation collisions.
- Importing the same binary and method-map hashes twice changes no rows and returns the existing import identifier.
- Query results are ordered deterministically by assembly, type, signature, and RVA.
- Index-only commands start no Cpp2IL, Ghidra, or Frida subprocess.

---

## Task 1: Define Typed Records and SQLite Schema

**Files:**
- Create: `src/retoolkit/re_index/__init__.py`
- Create: `src/retoolkit/re_index/models.py`
- Create: `src/retoolkit/re_index/schema.py`
- Create: `schemas/re_index_v1.sql`
- Create: `tests/test_re_index_schema.py`

**Interfaces:**
- Consumes: `pathlib.Path`, normalized method-map field names.
- Produces: `MethodRecord`, `ArtifactRecord`, `TargetQuery`, `SCHEMA_VERSION`, `MIGRATIONS`.

- [ ] **Step 1: Write failing model and migration tests**

```python
from retoolkit.re_index.models import MethodRecord, TargetQuery
from retoolkit.re_index.schema import MIGRATIONS, SCHEMA_VERSION


def test_schema_v1_contains_required_tables() -> None:
    sql = "\n".join(MIGRATIONS[1])
    for table in ("runs", "tools", "binaries", "method_maps", "methods",
                  "targets", "artifacts"):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in sql
    assert SCHEMA_VERSION == 1


def test_target_query_rejects_empty_selector() -> None:
    with pytest.raises(ValueError, match="at least one selector"):
        TargetQuery()


def test_method_record_preserves_collision_key() -> None:
    method = MethodRecord(1, "Assembly-CSharp", "N.T", "M",
                          "System.Void N.T::M()", 0x1234, 0x180001234, "id#0")
    assert method.rva == 0x1234
    assert method.collision_key == "id#0"
```

- [ ] **Step 2: Run the focused tests and verify import failures**

Run: `py -3.13 -m pytest tests/test_re_index_schema.py -q`
Expected: collection fails because `retoolkit.re_index` does not exist.

- [ ] **Step 3: Implement the records**

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class MethodRecord:
    id: int
    assembly: str
    type_name: str
    method_name: str
    signature: str
    rva: int
    pointer: int | None
    collision_key: str


@dataclass(frozen=True)
class ArtifactRecord:
    logical_name: str
    path: str
    sha256: str
    producer: str
    run_id: str


@dataclass(frozen=True)
class TargetQuery:
    assembly: str | None = None
    namespace: str | None = None
    type_pattern: str | None = None
    method_pattern: str | None = None
    identity: str | None = None
    rva: int | None = None
    limit: int = 100

    def __post_init__(self) -> None:
        selectors = (self.assembly, self.namespace, self.type_pattern,
                     self.method_pattern, self.identity, self.rva)
        if not any(value is not None for value in selectors):
            raise ValueError("at least one selector is required")
        if not 1 <= self.limit <= 10000:
            raise ValueError("limit must be between 1 and 10000")
```

- [ ] **Step 4: Implement schema version 1**

`schemas/re_index_v1.sql` must create the seven required tables, foreign
keys, uniqueness constraints, and indexes. Use these keys exactly:

```sql
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,
  profile_name TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  created_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS binaries (
  id INTEGER PRIMARY KEY,
  sha256 TEXT NOT NULL UNIQUE,
  path TEXT NOT NULL,
  image_base INTEGER,
  architecture TEXT
);
CREATE TABLE IF NOT EXISTS method_maps (
  id INTEGER PRIMARY KEY,
  binary_id INTEGER NOT NULL REFERENCES binaries(id),
  sha256 TEXT NOT NULL,
  method_count INTEGER NOT NULL,
  imported_utc TEXT NOT NULL,
  UNIQUE(binary_id, sha256)
);
CREATE TABLE IF NOT EXISTS methods (
  id INTEGER PRIMARY KEY,
  method_map_id INTEGER NOT NULL REFERENCES method_maps(id) ON DELETE CASCADE,
  assembly TEXT NOT NULL,
  type_name TEXT NOT NULL,
  method_name TEXT NOT NULL,
  signature TEXT NOT NULL,
  rva INTEGER NOT NULL,
  pointer INTEGER,
  full_identity TEXT NOT NULL,
  collision_key TEXT NOT NULL,
  UNIQUE(method_map_id, collision_key)
);
CREATE INDEX IF NOT EXISTS ix_methods_identity ON methods(full_identity);
CREATE INDEX IF NOT EXISTS ix_methods_rva ON methods(rva);
CREATE INDEX IF NOT EXISTS ix_methods_type_method ON methods(type_name, method_name);
CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY,
  method_id INTEGER NOT NULL REFERENCES methods(id),
  requested_depth TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL DEFAULT 'pending',
  UNIQUE(method_id, requested_depth)
);
CREATE TABLE IF NOT EXISTS tools (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  sha256 TEXT,
  UNIQUE(name, version, sha256)
);
CREATE TABLE IF NOT EXISTS artifacts (
  id INTEGER PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id),
  logical_name TEXT NOT NULL,
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  producer TEXT NOT NULL,
  UNIQUE(run_id, logical_name, sha256)
);
PRAGMA user_version = 1;
```

`schema.py` loads this resource and exposes `MIGRATIONS = {1: SQL_TEXT}`.

- [ ] **Step 5: Run tests and commit**

Run: `py -3.13 -m pytest tests/test_re_index_schema.py -q`
Expected: all tests pass.

```bash
git add src/retoolkit/re_index schemas/re_index_v1.sql tests/test_re_index_schema.py
git commit -m "feat: define REToolkit RE index schema"
```

## Task 2: Implement Transactional Store and Idempotent Method-Map Import

**Files:**
- Create: `src/retoolkit/re_index/store.py`
- Create: `src/retoolkit/re_index/importers.py`
- Create: `tests/test_re_index_store.py`
- Create: `tests/test_re_index_import.py`

**Interfaces:**
- Consumes: `MethodRecord`, normalized method-map document, binary and map hashes.
- Produces: `ReIndex.open`, `ReIndex.transaction`, `import_method_map`.

- [ ] **Step 1: Write failing transaction and migration tests**

```python
def test_open_migrates_empty_database(tmp_path) -> None:
    with ReIndex.open(tmp_path / "retoolkit.db") as index:
        assert index.user_version == 1
        assert index.scalar("SELECT COUNT(*) FROM methods") == 0


def test_failed_transaction_rolls_back(tmp_path) -> None:
    with ReIndex.open(tmp_path / "retoolkit.db") as index:
        with pytest.raises(RuntimeError):
            with index.transaction():
                index.execute("INSERT INTO runs VALUES (?, ?, ?, ?)",
                              ("r", "p", "h", "2026-08-01T00:00:00Z"))
                raise RuntimeError("stop")
        assert index.scalar("SELECT COUNT(*) FROM runs") == 0
```

- [ ] **Step 2: Run focused tests and confirm missing `ReIndex`**

Run: `py -3.13 -m pytest tests/test_re_index_store.py -q`
Expected: import failure for `ReIndex`.

- [ ] **Step 3: Implement `ReIndex`**

```python
class ReIndex:
    def __init__(self, path: Path, connection: sqlite3.Connection) -> None:
        self.path = path
        self.connection = connection
        self.connection.row_factory = sqlite3.Row

    @classmethod
    def open(cls, path: Path) -> "ReIndex":
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        index = cls(path, connection)
        index._migrate()
        return index

    @contextmanager
    def transaction(self):
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield self
        except BaseException:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()

    def __enter__(self) -> "ReIndex":
        return self

    def __exit__(self, *_: object) -> None:
        self.connection.close()
```

`_migrate()` reads `PRAGMA user_version`, rejects versions newer than the
program, and applies each missing migration inside one transaction.

- [ ] **Step 4: Write failing idempotent-import and collision tests**

```python
def test_import_is_idempotent_and_preserves_rva_collisions(tmp_path) -> None:
    document = {
        "schema_version": "1.0.0", "method_count": 2, "methods": [
            {"assembly": "A", "type": "N.T", "method": "M",
             "signature": "System.Void N.T::M()", "rva": "0x10",
             "pointer": "0x180000010", "full_identity": "A!System.Void N.T::M()"},
            {"assembly": "A", "type": "N.T", "method": "M",
             "signature": "System.Void N.T::M()", "rva": "0x20",
             "pointer": "0x180000020", "full_identity": "A!System.Void N.T::M()"},
        ],
    }
    with ReIndex.open(tmp_path / "i.db") as index:
        first = import_method_map(index, document, run_id="r", profile_name="p",
                                  input_hash="i", binary_path="b.dll",
                                  binary_sha256="b" * 64, method_map_sha256="m" * 64)
        second = import_method_map(index, document, run_id="r", profile_name="p",
                                   input_hash="i", binary_path="b.dll",
                                   binary_sha256="b" * 64, method_map_sha256="m" * 64)
        assert first == second
        assert index.scalar("SELECT COUNT(*) FROM methods") == 2
```

- [ ] **Step 5: Implement streaming import**

`import_method_map()` validates `method_count`, canonicalizes hex with
`int(value, 16)`, computes collision keys as
`<full_identity>#<lowercase-rva>`, inserts methods in batches of 5000 using
`executemany`, and returns the existing map ID on a duplicate map hash.

```python
def import_method_map(index: ReIndex, document: dict, *, run_id: str,
                      profile_name: str, input_hash: str, binary_path: str,
                      binary_sha256: str, method_map_sha256: str) -> int:
    methods = document.get("methods")
    if not isinstance(methods, list) or document.get("method_count") != len(methods):
        raise ResultError.validation("normalized method map count mismatch")
    with index.transaction():
        index.ensure_run(run_id, profile_name, input_hash)
        binary_id = index.ensure_binary(binary_sha256, binary_path)
        existing = index.find_method_map(binary_id, method_map_sha256)
        if existing is not None:
            return existing
        map_id = index.insert_method_map(binary_id, method_map_sha256, len(methods))
        index.insert_methods(map_id, methods)
        return map_id
```

- [ ] **Step 6: Run store/import tests and commit**

Run: `py -3.13 -m pytest tests/test_re_index_store.py tests/test_re_index_import.py -q`
Expected: all tests pass.

```bash
git add src/retoolkit/re_index/store.py src/retoolkit/re_index/importers.py tests/test_re_index_store.py tests/test_re_index_import.py
git commit -m "feat: import method maps into RE index"
```

## Task 3: Implement Deterministic Target Queries

**Files:**
- Create: `src/retoolkit/re_index/query.py`
- Create: `tests/test_target_query.py`

**Interfaces:**
- Consumes: `ReIndex`, `TargetQuery`.
- Produces: `resolve(index, query) -> list[MethodRecord]`, `parse_identity(text)`.

- [ ] **Step 1: Write failing exact, wildcard, namespace and RVA tests**

```python
@pytest.mark.parametrize(
    ("query", "expected_rvas"),
    [
        (TargetQuery(identity="A!System.Void N.T::M()"), [0x10, 0x20]),
        (TargetQuery(type_pattern="N.*", method_pattern="M"), [0x10, 0x20]),
        (TargetQuery(namespace="N", method_pattern="Get*"), [0x30]),
        (TargetQuery(rva=0x20), [0x20]),
    ],
)
def test_resolve_filters_and_orders(index_fixture, query, expected_rvas) -> None:
    assert [item.rva for item in resolve(index_fixture, query)] == expected_rvas
```

- [ ] **Step 2: Run and verify missing query module**

Run: `py -3.13 -m pytest tests/test_target_query.py -q`
Expected: import failure.

- [ ] **Step 3: Implement escaped wildcard translation and parameterized SQL**

```python
def _like(pattern: str) -> str:
    escaped = pattern.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return escaped.replace("*", "%").replace("?", "_")


def resolve(index: ReIndex, query: TargetQuery) -> list[MethodRecord]:
    clauses: list[str] = []
    values: list[object] = []
    # Append only parameterized predicates; derive namespace from type_name
    # with exact prefix `namespace + '.'`.
    sql = "SELECT id, assembly, type_name, method_name, signature, rva, pointer, collision_key FROM methods"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY assembly, type_name, signature, rva LIMIT ?"
    values.append(query.limit)
    return [MethodRecord(**dict(row)) for row in index.query(sql, values)]
```

Complete the function for all six selectors and use `LIKE ? ESCAPE '\\'` for
wildcards. Exact identity and RVA queries return every preserved collision.

- [ ] **Step 4: Add malformed-query and injection regression tests**

```python
def test_query_text_is_never_executed_as_sql(index_fixture) -> None:
    result = resolve(index_fixture, TargetQuery(method_pattern="M%' OR 1=1 --"))
    assert result == []
    assert index_fixture.scalar("SELECT COUNT(*) FROM methods") == 3
```

- [ ] **Step 5: Run query tests and commit**

Run: `py -3.13 -m pytest tests/test_target_query.py -q`
Expected: all tests pass.

```bash
git add src/retoolkit/re_index/query.py tests/test_target_query.py
git commit -m "feat: resolve indexed RE targets"
```

## Task 4: Add Index and Target CLI Commands

**Files:**
- Create: `src/retoolkit/commands/index.py`
- Create: `src/retoolkit/commands/target.py`
- Modify: `src/retoolkit/cli.py`
- Modify: `schemas/profile.schema.json`
- Modify: `profiles/everlusting/profile.json`
- Create: `tests/test_cli_re_index.py`
- Modify: `tests/test_cli_contract.py`
- Modify: `tests/test_profile.py`

**Interfaces:**
- Consumes: profile and `profile.workspace / "normalize" / "method-map.normalized.json"`.
- Produces: canonical JSON commands `index build`, `index stats`, `target resolve`, `target search`.

- [ ] **Step 1: Write failing parser and JSON-envelope tests**

```python
def test_index_build_parser_contract() -> None:
    args = build_parser().parse_args(["index", "build", "profile.json"])
    assert args.index_command == "build"


def test_target_resolve_returns_canonical_json(tmp_path, capsys) -> None:
    code = main(["target", "resolve", str(PROFILE), "A!System.Void N.T::M()"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 0
    assert doc["status"] == "ok"
    assert doc["command"] == "target resolve"
    assert doc["data"]["matches"][0]["rva"] == "0x10"
```

- [ ] **Step 2: Run the focused tests and verify parser rejection**

Run: `py -3.13 -m pytest tests/test_cli_re_index.py -q`
Expected: parser rejects `index` and `target`.

- [ ] **Step 3: Implement command handlers**

```python
def build_index(profile_path: Path) -> dict:
    profile = load_profile(profile_path)
    map_path = profile.workspace / "normalize" / "method-map.normalized.json"
    document = json.loads(map_path.read_text(encoding="utf-8"))
    binary_sha = sha256_file(profile.game_assembly)
    map_sha = sha256_file(map_path)
    db_path = profile.workspace / "re-index" / "retoolkit.db"
    with ReIndex.open(db_path) as index:
        map_id = import_method_map(
            index, document, run_id=make_run_id(), profile_name=profile.name,
            input_hash=hash_inputs([binary_sha, map_sha]),
            binary_path=str(profile.game_assembly), binary_sha256=binary_sha,
            method_map_sha256=map_sha,
        )
        count = index.scalar("SELECT COUNT(*) FROM methods WHERE method_map_id = ?", (map_id,))
    return {"database": str(db_path), "method_map_id": map_id, "method_count": count}
```

Handlers wrap these service functions with `Result.ok`. `target search` accepts
`--assembly`, `--namespace`, `--class`, `--method`, `--rva`, and `--limit`.
`target resolve` accepts one exact identity and an optional `--limit`.

- [ ] **Step 4: Register parsers without expanding handler logic in `cli.py`**

Add `register_index_commands(sub)` and `register_target_commands(sub)` imports;
each command module owns its subparser definitions and handler functions.

- [ ] **Step 5: Extend the profile schema**

Add an `index` object with:

```json
{
  "database": {"type": "string", "minLength": 1},
  "query_limit": {"type": "integer", "minimum": 1, "maximum": 10000}
}
```

The current profile uses `${RETOOLKIT_WORKSPACE}/re-index/retoolkit.db` and
`query_limit: 100`. Path resolution remains under the configured workspace.

- [ ] **Step 6: Run CLI/profile tests and commit**

Run: `py -3.13 -m pytest tests/test_cli_re_index.py tests/test_cli_contract.py tests/test_profile.py -q`
Expected: all tests pass; stdout remains one JSON document.

```bash
git add src/retoolkit/commands/index.py src/retoolkit/commands/target.py src/retoolkit/cli.py schemas/profile.schema.json profiles/everlusting/profile.json tests/test_cli_re_index.py tests/test_cli_contract.py tests/test_profile.py
git commit -m "feat: add indexed target query commands"
```

## Task 5: Integrate Cpp2IL Output, Evidence, and Live Acceptance

**Files:**
- Modify: `src/retoolkit/core/pipeline.py`
- Modify: `src/retoolkit/core/evidence.py`
- Create: `tests/integration/test_re_index_e2e.py`
- Create: `tests/live/test_re_index_live.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: normalized method map and binary hash after the existing normalize stage.
- Produces: indexed method count and evidence record without making Ghidra/Frida mandatory.

- [ ] **Step 1: Write failing mocked pipeline integration test**

```python
def test_pipeline_indexes_normalized_map_without_optional_tools(profile, fake_cpp2il) -> None:
    profile.stages.update({"frida": False, "ghidra": False})
    result = run_pipeline(profile, force_restart=True)
    assert Path(profile.workspace, "re-index", "retoolkit.db").is_file()
    assert any(stage["name"] == "index" and stage["status"] == "completed"
               for stage in result["stages"])
```

- [ ] **Step 2: Add `index` after `normalize` in the pipeline stage order**

Set:

```python
STAGES = ["validate", "fixup", "cpp2il", "normalize", "index", "frida", "ghidra", "evidence"]
```

The index stage calls the Phase 1 service directly, adds the SQLite database to
evidence only after closing the connection/checkpointing WAL, and records the
method count.

- [ ] **Step 3: Add the gated current-build live test**

```python
@pytest.mark.live
def test_current_build_indexes_all_methods(tmp_path) -> None:
    enabled, reason = gate_enabled("cpp2il")
    if not enabled:
        pytest.skip(reason)
    result = build_index(Path(os.environ["RETOOLKIT_PROFILE"]))
    assert result["method_count"] == 206366
```

- [ ] **Step 4: Run focused and full non-live suites**

Run: `py -3.13 -m pytest tests/integration/test_re_index_e2e.py tests/test_pipeline.py -q`
Expected: all focused tests pass.

Run: `py -3.13 -m pytest -q`
Expected: all non-live tests pass; only gated live tests skip.

- [ ] **Step 5: Run the current-build live gate**

```powershell
$env:RETOOLKIT_LIVE_CPP2IL='1'
$env:RETOOLKIT_PROFILE='D:\VSCode\REToolkit\profiles\everlusting\profile.json'
py -3.13 -m pytest tests\live\test_re_index_live.py -v
```

Expected: one test passes and reports `206366` indexed methods.

- [ ] **Step 6: Verify index-only queries launch no external tools**

Run target queries with fake executables that fail if started. Expected: query
exit `0`, fake invocation count `0`.

- [ ] **Step 7: Commit Phase 1**

```bash
git add src/retoolkit/core/pipeline.py src/retoolkit/core/evidence.py tests/integration/test_re_index_e2e.py tests/live/test_re_index_live.py README.md
git commit -m "feat: integrate RE index into analysis pipeline"
```

## Phase 1 Verification and Rollback

- Produce `phase-1-re-index.patch`, `phase-1-verification.md`,
  `phase-1-rollback.ps1`, and `phase-1-artifact-manifest.json`.
- Replay the patch into a fresh temporary repository and run Phase 1 tests.
- Rollback removes only Phase 1-created files, restores modified shared files
  from recorded hashes, and leaves `Analysis` and later-phase artifacts alone.
- Reopen the SQLite database with `PRAGMA integrity_check`; expected literal
  output is `ok`.
