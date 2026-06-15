"""Shared pytest fixtures and helpers for the validator test-suite.

These helpers build minimal :class:`Finding` / context objects so each test
reads as "given this finding on this evidence source, the validator should …".
Nothing here touches real evidence — the validators are pure, deterministic
code, which is exactly what makes them testable without a SIFT Workstation.
"""

from __future__ import annotations

import datetime

from sift_sentinel.evidence_graph.models import (
    EvidenceAnchor,
    Finding,
    FindingStatus,
)


def make_anchor(
    *,
    source_id: str = "src-001",
    artifact_path: str | None = None,
    file_hash: str | None = None,
    offset: str | None = None,
    log_entry: str | None = None,
) -> EvidenceAnchor:
    """Build an EvidenceAnchor, defaulting to a harmless log entry if empty.

    EvidenceAnchor requires at least one concrete reference, so when a test
    only cares about (say) a hash, we still give it a placeholder log entry.
    """
    if artifact_path is None and offset is None and log_entry is None:
        log_entry = "placeholder"
    return EvidenceAnchor(
        source_id=source_id,
        tool_execution_id="exec-001",
        artifact_path=artifact_path,
        file_hash=file_hash,
        offset=offset,
        log_entry=log_entry,
    )


def make_finding(
    *,
    finding_id: str = "F-001",
    category: str = "",
    summary: str = "test finding",
    anchor: EvidenceAnchor | None = None,
) -> Finding:
    """Build a HYPOTHESIS finding with the given anchor."""
    return Finding(
        finding_id=finding_id,
        status=FindingStatus.HYPOTHESIS,
        category=category,
        summary=summary,
        evidence_anchor=anchor,
    )


def source_dict(
    *,
    source_id: str = "src-001",
    os_type: str | None = None,
    filesystem_type: str | None = None,
    capture_time: str | None = None,
    os_install_time: str | None = None,
    mounted_at: str | None = None,
) -> dict:
    """Build an evidence-source dict shaped like EvidenceSource.to_dict()."""
    metadata: dict = {}
    if os_type is not None:
        metadata["os_type"] = os_type
    if filesystem_type is not None:
        metadata["filesystem_type"] = filesystem_type
    if capture_time is not None:
        metadata["capture_time"] = capture_time
    if os_install_time is not None:
        metadata["os_install_time"] = os_install_time
    return {
        "source_id": source_id,
        "source_type": "disk_image",
        "path": "/evidence/image.raw",
        "sha256": "sha256:" + "0" * 64,
        "mounted_at": mounted_at or "/mnt/evidence",
        "metadata": metadata,
    }


def iso(year, month, day, hour=0, minute=0) -> str:
    """Build a UTC ISO-8601 timestamp string."""
    return datetime.datetime(
        year, month, day, hour, minute, tzinfo=datetime.timezone.utc
    ).isoformat()
