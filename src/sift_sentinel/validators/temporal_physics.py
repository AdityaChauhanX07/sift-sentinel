"""Temporal physics validator.

Checks whether timestamps associated with a finding are physically possible
within the evidence timeline. A timestamp after the evidence was captured is a
logical impossibility (hard failure). A timestamp before OS installation, or a
timestamp duplicated across findings, is suspicious but not impossible (soft).
"""

from __future__ import annotations

import datetime
import re

from .base import BaseValidator, ValidatorVerdict
from ..evidence_graph.models import Finding


class TemporalPhysicsValidator(BaseValidator):
    """Validates finding timestamps against the evidence capture/install timeline."""

    @property
    def name(self) -> str:
        """Identifier used as ValidationResult.validator_name."""
        return "temporal_physics"

    @property
    def description(self) -> str:
        """One-line description of the check."""
        return (
            "Checks whether finding timestamps are physically possible within "
            "the evidence timeline"
        )

    @staticmethod
    def _parse_timestamp(ts: str) -> datetime.datetime | None:
        """Parse an ISO 8601-ish timestamp into a tz-aware datetime, or None.

        Accepts trailing ``Z``, explicit offsets, fractional seconds, and a
        space-separated date/time. Naive results are assumed UTC. Never raises.
        """
        if not isinstance(ts, str):
            return None
        candidate = ts.strip()
        if not candidate:
            return None
        # Quick sanity gate: must look like a date (YYYY-MM-DD) near the start.
        if not re.match(r"^\d{4}-\d{2}-\d{2}", candidate):
            return None
        # Normalize trailing Z to an explicit UTC offset for fromisoformat.
        if candidate.endswith("Z"):
            candidate = candidate[:-1] + "+00:00"
        try:
            parsed = datetime.datetime.fromisoformat(candidate)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        return parsed

    def validate(self, finding: Finding, context: dict):
        """Return a ValidationResult assessing the finding's temporal plausibility."""
        try:
            return self._validate(finding, context)
        except Exception as exc:  # never crash — degrade to NOT_APPLICABLE
            return self._make_result(
                ValidatorVerdict.NOT_APPLICABLE,
                f"Validator error, treated as not applicable: {exc}",
            )

    def _validate(self, finding: Finding, context: dict):
        anchor = finding.evidence_anchor
        if anchor is None:
            return self._make_result(
                ValidatorVerdict.NOT_APPLICABLE,
                "No evidence anchor — cannot check timestamps.",
            )

        source = self._find_source(anchor.source_id, context)
        metadata = (source.get("metadata") or {}) if source else {}
        capture_time = self._parse_timestamp(metadata.get("capture_time", ""))
        os_install_time = self._parse_timestamp(metadata.get("os_install_time", ""))

        finding_timestamps = context.get("finding_timestamps")
        has_timestamps = isinstance(finding_timestamps, list) and len(finding_timestamps) > 0

        if capture_time is None and not has_timestamps:
            return self._make_result(
                ValidatorVerdict.NOT_APPLICABLE,
                "No capture time or finding timestamps available for temporal "
                "validation.",
            )

        soft_anomalies: list[str] = []

        if has_timestamps:
            for raw_ts in finding_timestamps:
                parsed = self._parse_timestamp(raw_ts)
                if parsed is None:
                    continue  # unparseable timestamps are skipped, not failed

                # Hard impossibility: artifact dated after the evidence existed.
                if capture_time is not None and parsed > capture_time:
                    return self._make_result(
                        ValidatorVerdict.FAIL_HARD,
                        f"Timestamp {raw_ts} is after evidence capture time "
                        f"{metadata.get('capture_time')} — physically impossible.",
                    )

                # Soft anomaly: artifact predates the OS installation.
                if os_install_time is not None and parsed < os_install_time:
                    soft_anomalies.append(
                        f"timestamp {raw_ts} predates OS install "
                        f"({metadata.get('os_install_time')})"
                    )

            # Soft anomaly: same timestamp string reused across findings.
            self._collect_duplicate_anomalies(
                finding.finding_id, finding_timestamps, context, soft_anomalies
            )

        if soft_anomalies:
            return self._make_result(
                ValidatorVerdict.FAIL_SOFT,
                "Anomalies detected: " + "; ".join(soft_anomalies) + ".",
            )

        if not has_timestamps:
            # capture_time existed but there was nothing to check it against.
            return self._make_result(
                ValidatorVerdict.NOT_APPLICABLE,
                "No finding timestamps provided for validation.",
            )

        return self._make_result(
            ValidatorVerdict.PASS,
            "All timestamps are within the valid evidence timeline.",
        )

    # --- helpers ---

    @staticmethod
    def _find_source(source_id: str, context: dict) -> dict | None:
        for source in context.get("evidence_sources", []) or []:
            if source.get("source_id") == source_id:
                return source
        return None

    @staticmethod
    def _collect_duplicate_anomalies(
        finding_id: str,
        finding_timestamps: list,
        context: dict,
        soft_anomalies: list,
    ) -> None:
        all_ts = context.get("all_finding_timestamps")
        if not isinstance(all_ts, dict):
            return
        for ts in finding_timestamps:
            for other_id, other_list in all_ts.items():
                if other_id == finding_id:
                    continue
                if isinstance(other_list, list) and ts in other_list:
                    soft_anomalies.append(
                        f"timestamp {ts} duplicated in finding {other_id}"
                    )
                    break
