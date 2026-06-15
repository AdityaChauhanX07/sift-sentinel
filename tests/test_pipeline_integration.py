"""End-to-end test of the default validator pipeline against the evidence graph.

This is the contract the README sells: a hallucinated finding enters the graph
as a HYPOTHESIS, the deterministic pipeline runs, a hard failure is recorded on
the finding, and the caller eliminates it. We exercise the *real* default
pipeline (all five validators) and the *real* graph manager — no mocks.
"""

from __future__ import annotations

from sift_sentinel.validators.factory import create_default_pipeline
from sift_sentinel.evidence_graph.graph import EvidenceGraphManager
from sift_sentinel.evidence_graph.models import (
    EvidenceAnchor,
    FindingStatus,
    ValidatorVerdict,
)

from .conftest import source_dict


def test_default_pipeline_has_five_validators():
    pipeline = create_default_pipeline()
    # The pipeline keeps its registered validators on ._validators.
    assert len(pipeline._validators) == 5


def test_hallucinated_windows_finding_on_linux_is_eliminated():
    """A Windows registry finding on a Linux image is caught and eliminated."""
    mgr = EvidenceGraphManager("TEST-PIPELINE")

    anchor = EvidenceAnchor(
        source_id="src-001",
        tool_execution_id="exec-001",
        artifact_path="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    )
    finding = mgr.add_finding(
        summary="Run key persistence on a Linux disk image (impossible)",
        category="registry_artifact",
        evidence_anchor=anchor,
    )
    assert finding.status == FindingStatus.HYPOTHESIS

    pipeline = create_default_pipeline()
    context = {
        "evidence_sources": [
            source_dict(os_type="Linux", filesystem_type="ext4")
        ],
        "raw_outputs": {},
    }

    results = pipeline.validate_finding(finding, context)
    for r in results:
        mgr.add_validation_result(finding.finding_id, r)

    hard = [r for r in results if r.verdict == ValidatorVerdict.FAIL_HARD]
    assert hard, "expected platform_consistency to hard-fail"

    mgr.eliminate_finding(
        finding.finding_id,
        reason=f"Validator: {hard[0].detail}",
        triggered_by=f"validator:{hard[0].validator_name}",
    )

    refreshed = mgr.get_finding(finding.finding_id)
    assert refreshed.status == FindingStatus.ELIMINATED
    # The validation result is preserved on the finding for the audit trail.
    assert any(
        v.validator_name == "platform_consistency"
        and v.verdict == ValidatorVerdict.FAIL_HARD
        for v in refreshed.validation_results
    )


def test_legitimate_windows_finding_survives_pipeline():
    """A plausible Windows finding on an NTFS image is not eliminated."""
    mgr = EvidenceGraphManager("TEST-PIPELINE-OK")

    anchor = EvidenceAnchor(
        source_id="src-001",
        tool_execution_id="exec-001",
        artifact_path="C:\\Windows\\System32\\config\\SOFTWARE",
    )
    finding = mgr.add_finding(
        summary="SOFTWARE hive present on Windows image",
        category="registry_artifact",
        evidence_anchor=anchor,
    )

    pipeline = create_default_pipeline()
    context = {
        "evidence_sources": [
            source_dict(os_type="Windows", filesystem_type="NTFS")
        ],
        "raw_outputs": {},
    }

    results = pipeline.validate_finding(finding, context)
    for r in results:
        mgr.add_validation_result(finding.finding_id, r)

    assert not any(r.verdict == ValidatorVerdict.FAIL_HARD for r in results)
    assert mgr.get_finding(finding.finding_id).status == FindingStatus.HYPOTHESIS
