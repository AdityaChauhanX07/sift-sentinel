"""Tests for the PlatformConsistencyValidator.

The thesis of SIFT Sentinel is that a Windows artifact claimed on a Linux image
is a *logical impossibility* — a hallucination the code can eliminate without an
LLM. These tests pin that behaviour down.
"""

from __future__ import annotations

from sift_sentinel.validators.platform_consistency import (
    PlatformConsistencyValidator,
)
from sift_sentinel.evidence_graph.models import ValidatorVerdict

from .conftest import make_anchor, make_finding, source_dict


def _run(finding, source):
    validator = PlatformConsistencyValidator()
    return validator.validate(finding, {"evidence_sources": [source]})


def test_windows_registry_on_linux_image_is_hard_fail():
    """A Windows registry path on an ext4/Linux source must be eliminated."""
    finding = make_finding(
        category="registry_artifact",
        anchor=make_anchor(
            artifact_path="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        ),
    )
    source = source_dict(os_type="Linux", filesystem_type="ext4")

    result = _run(finding, source)

    assert result.verdict == ValidatorVerdict.FAIL_HARD
    assert "logical impossibility" in result.detail


def test_windows_artifact_on_windows_image_passes():
    """The same artifact on an NTFS/Windows source is perfectly valid."""
    finding = make_finding(
        category="registry_artifact",
        anchor=make_anchor(
            artifact_path="C:\\Windows\\System32\\config\\SOFTWARE"
        ),
    )
    source = source_dict(os_type="Windows", filesystem_type="NTFS")

    result = _run(finding, source)

    assert result.verdict == ValidatorVerdict.PASS


def test_linux_path_on_windows_image_is_hard_fail():
    """A /etc/cron path on an NTFS/Windows source is impossible."""
    finding = make_finding(
        category="persistence",
        anchor=make_anchor(artifact_path="/etc/cron.d/backdoor"),
    )
    source = source_dict(os_type="Windows", filesystem_type="NTFS")

    result = _run(finding, source)

    assert result.verdict == ValidatorVerdict.FAIL_HARD


def test_drive_letter_path_detected_as_windows():
    """A bare drive-letter path (D:\\...) is recognised as a Windows artifact."""
    finding = make_finding(
        anchor=make_anchor(artifact_path="D:\\malware\\payload.exe")
    )
    source = source_dict(os_type="Linux", filesystem_type="ext4")

    result = _run(finding, source)

    assert result.verdict == ValidatorVerdict.FAIL_HARD


def test_missing_metadata_is_not_applicable():
    """Without OS/filesystem metadata the validator must abstain, not guess."""
    finding = make_finding(
        anchor=make_anchor(artifact_path="C:\\Windows\\System32\\cmd.exe")
    )
    source = source_dict()  # no os_type / filesystem_type

    result = _run(finding, source)

    assert result.verdict == ValidatorVerdict.NOT_APPLICABLE


def test_unknown_source_is_not_applicable():
    """If the anchor references a source not in context, the validator abstains."""
    finding = make_finding(
        anchor=make_anchor(
            source_id="src-999",
            artifact_path="C:\\Windows\\System32\\cmd.exe",
        )
    )
    source = source_dict(source_id="src-001", os_type="Windows")

    result = _run(finding, source)

    assert result.verdict == ValidatorVerdict.NOT_APPLICABLE


def test_no_anchor_is_not_applicable():
    """A finding with no evidence anchor cannot be platform-checked."""
    finding = make_finding(anchor=None)
    source = source_dict(os_type="Windows", filesystem_type="NTFS")

    result = _run(finding, source)

    assert result.verdict == ValidatorVerdict.NOT_APPLICABLE
