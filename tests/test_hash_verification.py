"""Tests for the HashVerificationValidator.

This validator independently recomputes a file's SHA-256 and compares it against
the agent's claim. A real file with a wrong claimed hash is the clearest possible
hallucination signal, so it is a hard failure. We use a tmp file as the "mounted
evidence" so the recomputation is real, not mocked.
"""

from __future__ import annotations

import hashlib

from sift_sentinel.validators.hash_verification import HashVerificationValidator
from sift_sentinel.evidence_graph.models import ValidatorVerdict

from .conftest import make_anchor, make_finding, source_dict


def _sha256_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _run(finding, source):
    validator = HashVerificationValidator()
    return validator.validate(finding, {"evidence_sources": [source]})


def test_matching_hash_passes(tmp_path):
    """A correct claimed hash on a readable file verifies clean."""
    payload = b"benign file contents"
    f = tmp_path / "evil.exe"
    f.write_bytes(payload)

    finding = make_finding(
        anchor=make_anchor(artifact_path="evil.exe", file_hash=_sha256_of(payload))
    )
    source = source_dict(mounted_at=str(tmp_path))

    result = _run(finding, source)

    assert result.verdict == ValidatorVerdict.PASS


def test_wrong_hash_is_hard_fail(tmp_path):
    """A fabricated hash on a real file must be eliminated."""
    f = tmp_path / "evil.exe"
    f.write_bytes(b"the actual bytes on disk")

    fabricated = "sha256:" + "a" * 64
    finding = make_finding(
        anchor=make_anchor(artifact_path="evil.exe", file_hash=fabricated)
    )
    source = source_dict(mounted_at=str(tmp_path))

    result = _run(finding, source)

    assert result.verdict == ValidatorVerdict.FAIL_HARD
    assert "MISMATCH" in result.detail


def test_missing_file_is_soft_fail(tmp_path):
    """A hash claim against a file that isn't there is unverifiable (soft)."""
    finding = make_finding(
        anchor=make_anchor(
            artifact_path="gone.exe", file_hash="sha256:" + "b" * 64
        )
    )
    source = source_dict(mounted_at=str(tmp_path))

    result = _run(finding, source)

    assert result.verdict == ValidatorVerdict.FAIL_SOFT


def test_no_hash_claim_is_not_applicable(tmp_path):
    """Nothing to verify when the anchor carries no hash."""
    finding = make_finding(
        anchor=make_anchor(artifact_path="evil.exe", file_hash=None)
    )
    source = source_dict(mounted_at=str(tmp_path))

    result = _run(finding, source)

    assert result.verdict == ValidatorVerdict.NOT_APPLICABLE


def test_md5_claim_is_not_applicable(tmp_path):
    """An MD5 claim is a different hash type — out of scope, not a failure."""
    f = tmp_path / "evil.exe"
    f.write_bytes(b"data")

    finding = make_finding(
        anchor=make_anchor(
            artifact_path="evil.exe", file_hash="md5:" + "c" * 32
        )
    )
    source = source_dict(mounted_at=str(tmp_path))

    result = _run(finding, source)

    assert result.verdict == ValidatorVerdict.NOT_APPLICABLE


def test_windows_path_resolves_under_mount(tmp_path):
    """A Windows-style claimed path resolves to a real file under the mount."""
    payload = b"system file"
    windows_dir = tmp_path / "Windows" / "System32"
    windows_dir.mkdir(parents=True)
    (windows_dir / "drv.sys").write_bytes(payload)

    finding = make_finding(
        anchor=make_anchor(
            artifact_path="C:\\Windows\\System32\\drv.sys",
            file_hash=_sha256_of(payload),
        )
    )
    source = source_dict(mounted_at=str(tmp_path))

    result = _run(finding, source)

    assert result.verdict == ValidatorVerdict.PASS
