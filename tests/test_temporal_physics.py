"""Tests for the TemporalPhysicsValidator.

A timestamp *after* the evidence was captured is physically impossible and must
be a hard failure; a timestamp before OS install, or one duplicated across
findings, is suspicious-but-possible (soft).
"""

from __future__ import annotations

from sift_sentinel.validators.temporal_physics import TemporalPhysicsValidator
from sift_sentinel.evidence_graph.models import ValidatorVerdict

from .conftest import make_anchor, make_finding, source_dict, iso


def _run(finding, source, **context):
    validator = TemporalPhysicsValidator()
    ctx = {"evidence_sources": [source]}
    ctx.update(context)
    return validator.validate(finding, ctx)


def test_timestamp_after_capture_is_hard_fail():
    """An artifact dated after the image was captured is impossible."""
    finding = make_finding(anchor=make_anchor(log_entry="event"))
    source = source_dict(capture_time=iso(2024, 1, 1, 12, 0))

    result = _run(
        finding, source, finding_timestamps=[iso(2024, 6, 1, 0, 0)]
    )

    assert result.verdict == ValidatorVerdict.FAIL_HARD
    assert "physically impossible" in result.detail


def test_timestamp_before_capture_passes():
    """A timestamp comfortably before capture time is valid."""
    finding = make_finding(anchor=make_anchor(log_entry="event"))
    source = source_dict(capture_time=iso(2024, 6, 1, 12, 0))

    result = _run(
        finding, source, finding_timestamps=[iso(2024, 1, 1, 0, 0)]
    )

    assert result.verdict == ValidatorVerdict.PASS


def test_timestamp_before_os_install_is_soft_fail():
    """An artifact predating OS install is anomalous but not impossible."""
    finding = make_finding(anchor=make_anchor(log_entry="event"))
    source = source_dict(
        capture_time=iso(2024, 6, 1, 12, 0),
        os_install_time=iso(2023, 1, 1, 0, 0),
    )

    result = _run(
        finding, source, finding_timestamps=[iso(2022, 1, 1, 0, 0)]
    )

    assert result.verdict == ValidatorVerdict.FAIL_SOFT
    assert "predates OS install" in result.detail


def test_z_suffix_timestamp_is_parsed():
    """A trailing-Z UTC timestamp must parse and still trip the hard check."""
    finding = make_finding(anchor=make_anchor(log_entry="event"))
    source = source_dict(capture_time="2024-01-01T00:00:00Z")

    result = _run(
        finding, source, finding_timestamps=["2024-12-31T23:59:59Z"]
    )

    assert result.verdict == ValidatorVerdict.FAIL_HARD


def test_unparseable_timestamp_is_skipped_not_failed():
    """Garbage timestamps are skipped, never treated as a violation."""
    finding = make_finding(anchor=make_anchor(log_entry="event"))
    source = source_dict(capture_time=iso(2024, 1, 1, 0, 0))

    result = _run(finding, source, finding_timestamps=["not-a-date"])

    # Nothing checkable remained -> PASS (no anomalies), not a failure.
    assert result.verdict == ValidatorVerdict.PASS


def test_no_capture_time_and_no_timestamps_is_not_applicable():
    """With nothing to compare, the validator abstains."""
    finding = make_finding(anchor=make_anchor(log_entry="event"))
    source = source_dict()

    result = _run(finding, source)

    assert result.verdict == ValidatorVerdict.NOT_APPLICABLE
