"""Linear resumable pipeline: validate -> fixup -> cpp2il -> normalize ->
optional frida/ghidra -> evidence. Sequential only; resume skips completed
stages whose input hashes still match."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from retoolkit.contracts.profile import Profile
from retoolkit.contracts.result import ResultError
from retoolkit.core.capabilities import discover, report, require
from retoolkit.core.evidence import EvidenceDir
from retoolkit.core.state import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_RUNNING,
    WorkspaceLock,
    hash_inputs,
)
from retoolkit.core.state import PipelineState

STAGES = ["validate", "fixup", "cpp2il", "normalize", "frida", "ghidra", "evidence"]
OPTIONAL_STAGES = {"frida", "ghidra"}


@dataclass
class StageOutcome:
    name: str
    status: str  # completed | skipped | failed
    reason: str | None = None
    artifacts: list[str] = field(default_factory=list)
    evidence: str | None = None


@dataclass
class PipelineContext:
    profile: Profile
    workspace: Path
    evidence: EvidenceDir
    capabilities: dict
    cpp2il_adapter: object | None = None
    ghidra_adapter: object | None = None
    frida_adapter: object | None = None


def plan(profile: Profile) -> dict:
    """List ordered stages with enabled state; never touches the workspace."""
    enabled = {
        "validate": True,
        "evidence": True,
        **{stage: bool(profile.stages.get(stage)) for stage in OPTIONAL_STAGES},
        "fixup": bool(profile.stages.get("fixup")),
        "cpp2il": bool(profile.stages.get("cpp2il")),
        "normalize": bool(profile.stages.get("cpp2il")),
    }
    return {
        "name": profile.name,
        "stages": [
            {"name": stage, "enabled": enabled[stage]} for stage in STAGES
        ],
    }


def compute_input_hash(profile: Profile, caps: dict) -> str:
    parts = [json.dumps(profile.raw, sort_keys=True)]
    for cap in caps.get("capabilities", []):
        parts.append(f"{cap['name']}={cap.get('version', '')}")
    for label, path in (("assembly", profile.game_assembly), ("metadata", profile.metadata)):
        if path.is_file():
            parts.append(hashlib.sha256(path.read_bytes()).hexdigest())
        else:
            parts.append(f"{label}:missing")
    return hash_inputs(parts)


def _stage_hash(profile: Profile, name: str, ctx: PipelineContext) -> str:
    parts = []
    if name == "validate":
        parts = [json.dumps(profile.raw, sort_keys=True)]
    elif name == "fixup":
        fixup = profile.raw.get("metadata_fixup", {})
        parts = [json.dumps(fixup, sort_keys=True)]
        if profile.metadata.is_file():
            parts.append(hashlib.sha256(profile.metadata.read_bytes()).hexdigest())
    elif name == "cpp2il":
        parts = [
            json.dumps(profile.raw.get("tools", {}).get("cpp2il", {}), sort_keys=True),
            str(profile.game_assembly),
        ]
        rebuilt = ctx.workspace / "fixup" / "global-metadata.rebuilt.dat"
        metadata = rebuilt if rebuilt.is_file() else profile.metadata
        if metadata.is_file():
            parts.append(hashlib.sha256(metadata.read_bytes()).hexdigest())
    elif name == "normalize":
        parts = [str(profile.raw.get("method_map_collision_policy", "report"))]
    elif name == "frida":
        parts = [json.dumps(profile.raw.get("analysis", {}), sort_keys=True)]
    elif name == "ghidra":
        parts = [json.dumps(profile.raw.get("analysis", {}), sort_keys=True), str(profile.game_assembly)]
    elif name == "evidence":
        parts = [str(ctx.evidence.run_id)]
    return hash_inputs(parts)


def _make_adapters(profile: Profile, caps: dict, *, include_ghidra: bool = False) -> dict:
    from retoolkit.adapters.cpp2il import Cpp2IlAdapter
    from retoolkit.adapters.frida import FridaAdapter
    from retoolkit.adapters.ghidra import GhidraAdapter

    cpp2il_cap = require(caps, "cpp2il")
    tool = profile.tools.get("cpp2il")
    cpp2il = Cpp2IlAdapter(
        Path(cpp2il_cap["path"]),
        plugin_dir=tool.plugin_dir if tool else None,
        timeout_seconds=tool.timeout_seconds if tool else 600,
    )
    ghidra = None
    ghidra_tool = profile.tools.get("ghidra")
    if include_ghidra and ghidra_tool and ghidra_tool.path:
        scripts_dir = Path(__file__).resolve().parents[2] / "ghidra_scripts"
        ghidra = GhidraAdapter(
            Path(ghidra_tool.path),
            scripts_dir=scripts_dir,
            timeout_seconds=ghidra_tool.timeout_seconds,
            image_base=profile.raw.get("analysis", {}).get("image_base", 0x180000000),
        )
    frida_timeout = 120
    frida_tool = profile.tools.get("frida")
    if frida_tool:
        frida_timeout = frida_tool.timeout_seconds
    frida = FridaAdapter(timeout_seconds=frida_timeout)
    return {"cpp2il": cpp2il, "ghidra": ghidra, "frida": frida}


def _run_stage(name: str, ctx: PipelineContext) -> StageOutcome:
    if name == "validate":
        return StageOutcome(name=name, status=STATUS_COMPLETED, artifacts=["inputs hashed"])
    if name == "fixup":
        fixup_doc = ctx.profile.raw.get("metadata_fixup")
        if not fixup_doc:
            return StageOutcome(name=name, status="skipped", reason="profile has no metadata_fixup")
        from retoolkit.metadata.mfuscator import FixupConfig, rebuild_file

        config = FixupConfig.from_doc(fixup_doc)
        output = ctx.workspace / "fixup" / "global-metadata.rebuilt.dat"
        output.parent.mkdir(parents=True, exist_ok=True)
        report_data = rebuild_file(ctx.profile.metadata, output, config)
        record = ctx.evidence.add_file(
            logical_name="global-metadata.rebuilt.dat", source=output, stage="fixup", tool="retoolkit"
        )
        return StageOutcome(name=name, status=STATUS_COMPLETED, evidence=record.artifact_path,
                            artifacts=[str(output)])
    if name == "cpp2il":
        rebuilt = ctx.workspace / "fixup" / "global-metadata.rebuilt.dat"
        metadata = rebuilt if rebuilt.is_file() else ctx.profile.metadata
        output_dir = ctx.workspace / "cpp2il"
        result = ctx.cpp2il_adapter.export_method_map(ctx.profile.game_assembly, metadata, output_dir)
        record = ctx.evidence.add_file(
            logical_name="method-pointer-map.json", source=result.map_path, stage="cpp2il", tool="cpp2il"
        )
        ctx.evidence.add_file(logical_name="cpp2il.log", source=result.log_path, stage="cpp2il", tool="cpp2il")
        return StageOutcome(name=name, status=STATUS_COMPLETED, evidence=record.artifact_path,
                            artifacts=[str(result.map_path)])
    if name == "normalize":
        from retoolkit.normalizers.method_map import normalize_file

        source = ctx.workspace / "cpp2il" / "method-pointer-map.json"
        if not source.is_file():
            return StageOutcome(name=name, status=STATUS_FAILED, reason="missing cpp2il map output")
        policy = ctx.profile.raw.get("method_map_collision_policy", "report")
        doc = normalize_file(source, collision_policy=policy)
        output = ctx.workspace / "normalize" / "method-map.normalized.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(doc, sort_keys=True, indent=1), encoding="utf-8")
        record = ctx.evidence.add_file(
            logical_name="method-map.normalized.json", source=output, stage="normalize", tool="retoolkit"
        )
        return StageOutcome(name=name, status=STATUS_COMPLETED, evidence=record.artifact_path,
                            artifacts=[str(output)])
    if name == "frida":
        if not ctx.profile.stages.get("frida"):
            return StageOutcome(name=name, status="skipped", reason="stage disabled")
        try:
            import frida as frida_module  # noqa: F401
        except ImportError:
            return StageOutcome(name=name, status="skipped", reason="frida module unavailable")
        targets = ctx.profile.raw.get("analysis", {}).get("frida_targets", [])
        if not targets:
            return StageOutcome(name=name, status="skipped", reason="no frida_targets configured")
        trace = Path(__file__).resolve().parents[2] / "profiles" / "examples" / "frida" / "method-list.js"
        messages = ctx.frida_adapter.run_trace(target=targets, trace_script=trace, params={"targets": targets})
        jsonl = ctx.workspace / "frida" / "trace.jsonl"
        ctx.frida_adapter.write_jsonl(messages, jsonl)
        record = ctx.evidence.add_file(logical_name="trace.jsonl", source=jsonl, stage="frida", tool="frida")
        return StageOutcome(name=name, status=STATUS_COMPLETED, evidence=record.artifact_path,
                            artifacts=[str(jsonl)])
    if name == "ghidra":
        if not ctx.profile.stages.get("ghidra"):
            return StageOutcome(name=name, status="skipped", reason="stage disabled")
        if ctx.ghidra_adapter is None:
            return StageOutcome(name=name, status="skipped", reason="ghidra capability missing")
        analysis = ctx.profile.raw.get("analysis", {})
        targets = analysis.get("ghidra_targets", [])
        if not targets:
            return StageOutcome(name=name, status="skipped", reason="no ghidra_targets configured")
        output_dir = ctx.workspace / "ghidra"
        result = ctx.ghidra_adapter.decompile_rvas(
            binary=ctx.profile.game_assembly,
            project_dir=ctx.workspace / "ghidra-projects",
            project_name="retoolkit",
            rvas=targets,
            output_dir=output_dir,
        )
        for artifact in result.artifacts:
            if artifact.path:
                ctx.evidence.add_file(logical_name=artifact.path.name, source=artifact.path,
                                      stage="ghidra", tool="ghidra")
        return StageOutcome(name=name, status=STATUS_COMPLETED,
                            artifacts=[a.path.name for a in result.artifacts if a.path])
    if name == "evidence":
        return StageOutcome(name=name, status=STATUS_COMPLETED, artifacts=[str(ctx.evidence.manifest_path)])
    raise ResultError.internal(f"unknown stage {name}")


def run_pipeline(profile: Profile, *, resume: bool = False, force_restart: bool = False) -> dict:
    workspace = profile.workspace
    workspace.mkdir(parents=True, exist_ok=True)
    caps = discover(cpp2il_path=profile.tools.get("cpp2il").path if profile.tools.get("cpp2il") else None,
                    ghidra_root=profile.tools.get("ghidra").path if profile.tools.get("ghidra") else None)
    caps_doc = report(caps)
    if profile.stages.get("cpp2il"):
        require(caps_doc, "cpp2il")

    input_hash = compute_input_hash(profile, caps_doc)
    state = PipelineState.load_or_create(
        workspace, STAGES, input_hash, force_restart=force_restart
    )
    with WorkspaceLock(workspace):
        evidence = EvidenceDir(base_dir=workspace / "evidence", run_id=state.run_id)
        ctx = PipelineContext(profile=profile, workspace=workspace, evidence=evidence, capabilities=caps_doc)
        if profile.stages.get("cpp2il") or profile.stages.get("fixup"):
            ctx.cpp2il_adapter = _make_adapters(profile, caps_doc)["cpp2il"]
        ctx.ghidra_adapter = _make_adapters(
            profile, caps_doc, include_ghidra=bool(profile.stages.get("ghidra"))
        )["ghidra"]
        ctx.frida_adapter = _make_adapters(profile, caps_doc)["frida"]
        outcomes: list[dict] = []
        for name in STAGES:
            stage_hash = _stage_hash(profile, name, ctx)
            if state.can_skip(name, stage_hash):
                outcomes.append({"name": name, "status": "resumed"})
                continue
            if name in OPTIONAL_STAGES and not profile.stages.get(name):
                outcomes.append({"name": name, "status": "skipped", "reason": "stage disabled"})
                continue
            state.set_status(name, STATUS_RUNNING)
            try:
                outcome = _run_stage(name, ctx)
            except Exception as exc:
                state.set_status(name, STATUS_FAILED)
                outcomes.append({"name": name, "status": "failed",
                                 "reason": f"{type(exc).__name__}: {exc}"})
                raise
            if outcome.status == STATUS_COMPLETED:
                state.set_status(name, STATUS_COMPLETED, input_hash=stage_hash, evidence=outcome.evidence)
            elif outcome.status == STATUS_FAILED:
                state.set_status(name, STATUS_FAILED)
                raise ResultError.validation(f"stage {name} failed: {outcome.reason}")
            outcomes.append({
                "name": name, "status": outcome.status, "reason": outcome.reason,
                "artifacts": outcome.artifacts,
            })
        return {
            "run_id": state.run_id,
            "input_hash": input_hash,
            "stages": outcomes,
            "evidence_manifest": str(evidence.manifest_path),
        }
