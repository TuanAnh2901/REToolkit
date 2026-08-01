"""Structural validation for reconstructed Mfuscator metadata candidates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Sequence

from .mfuscator_contract import MfuscatorContract


@dataclass(frozen=True)
class ValidationFinding:
    code: str
    severity: Literal["error", "warning", "info"]
    section: str | None
    message: str


@dataclass(frozen=True)
class ValidationReport:
    accepted: bool
    score: int
    findings: tuple[ValidationFinding, ...]

    def to_dict(self) -> dict:
        return {
            "accepted": self.accepted,
            "score": self.score,
            "findings": [
                {
                    "code": finding.code,
                    "severity": finding.severity,
                    "section": finding.section,
                    "message": finding.message,
                }
                for finding in self.findings
            ],
        }


def validate_candidate(
    data: bytes,
    contract: MfuscatorContract,
    descriptors: Sequence[tuple[int, int]],
) -> ValidationReport:
    findings: list[ValidationFinding] = []
    if len(descriptors) != len(contract.sections):
        findings.append(
            ValidationFinding(
                code="descriptor.count",
                severity="error",
                section=None,
                message=(
                    f"expected {len(contract.sections)} descriptors, got {len(descriptors)}"
                ),
            )
        )

    ranges: list[tuple[int, int, str]] = []
    successful_checks = 0
    for section, descriptor in zip(contract.sections, descriptors):
        offset, size = descriptor
        in_bounds = offset >= 0 and size >= 0 and offset + size <= len(data)
        if not in_bounds:
            findings.append(
                ValidationFinding(
                    code="section.bounds",
                    severity="error",
                    section=section.name,
                    message=f"{offset:#x} + {size:#x} exceeds input size {len(data):#x}",
                )
            )
        else:
            successful_checks += 1
        if offset % section.alignment:
            findings.append(
                ValidationFinding(
                    code="section.alignment",
                    severity="error",
                    section=section.name,
                    message=f"offset {offset:#x} is not aligned to {section.alignment}",
                )
            )
        else:
            successful_checks += 1
        if section.record_size is not None and size % section.record_size:
            findings.append(
                ValidationFinding(
                    code="section.record_size",
                    severity="error",
                    section=section.name,
                    message=f"size {size:#x} is not divisible by {section.record_size}",
                )
            )
        elif section.record_size is not None:
            successful_checks += 1
        if size > 0:
            ranges.append((offset, offset + size, section.name))

    ranges.sort(key=lambda item: (item[0], item[1], item[2]))
    for previous, current in zip(ranges, ranges[1:]):
        if current[0] < previous[1]:
            findings.append(
                ValidationFinding(
                    code="section.overlap",
                    severity="error",
                    section=current[2],
                    message=(
                        f"section {current[2]} starts at {current[0]:#x} before "
                        f"section {previous[2]} ends at {previous[1]:#x}"
                    ),
                )
            )

    error_count = sum(finding.severity == "error" for finding in findings)
    warning_count = sum(finding.severity == "warning" for finding in findings)
    return ValidationReport(
        accepted=error_count == 0,
        score=max(0, successful_checks - error_count * 100 - warning_count * 10),
        findings=tuple(findings),
    )
