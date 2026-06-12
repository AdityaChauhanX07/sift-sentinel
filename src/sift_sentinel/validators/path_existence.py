"""Path existence validator.

Best-effort verification that a finding's claimed artifact path actually exists
in the mounted evidence. Forensic paths are messy — 8.3 short names,
``\\Device\\HarddiskVolume`` paths, SYSVOL aliases, case-sensitivity
differences, deleted files in ``$I30`` — so this validator is SOFT ONLY. An
unresolved path means "couldn't verify," not "doesn't exist." It never returns
FAIL_HARD and never eliminates a finding.
"""

from __future__ import annotations

import os
import re

from .base import BaseValidator, ValidatorVerdict
from ..evidence_graph.models import Finding


# \Device\HarddiskVolume<N>\  (any volume number)
_HARDDISK_VOLUME_RE = re.compile(r"^\\device\\harddiskvolume\d+\\", re.IGNORECASE)
# \\?\C:\  and  \??\C:\  (extended-length / object-manager drive prefixes)
_EXTENDED_DRIVE_RE = re.compile(r"^\\(\\\?|\?\?)\\[a-z]:\\", re.IGNORECASE)
# \SystemRoot\  -> Windows\
_SYSTEMROOT_RE = re.compile(r"^\\systemroot\\", re.IGNORECASE)
# Leading drive letter, e.g. C:\
_DRIVE_LETTER_RE = re.compile(r"^[a-z]:\\", re.IGNORECASE)


class PathExistenceValidator(BaseValidator):
    """Verifies artifact paths against mounted evidence — SOFT only, best-effort."""

    @property
    def name(self) -> str:
        """Identifier used as ValidationResult.validator_name."""
        return "path_existence"

    @property
    def description(self) -> str:
        """One-line description of the check."""
        return (
            "Attempts to verify artifact path exists in mounted evidence — "
            "SOFT only, never eliminates"
        )

    def validate(self, finding: Finding, context: dict):
        """Return a ValidationResult; maximum severity is FAIL_SOFT."""
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
                ValidatorVerdict.NOT_APPLICABLE, "No evidence anchor."
            )

        artifact_path = anchor.artifact_path
        if not artifact_path:
            return self._make_result(
                ValidatorVerdict.NOT_APPLICABLE,
                "No artifact path to verify — finding may reference an offset or "
                "log entry instead.",
            )

        source = self._find_source(anchor.source_id, context)
        mounted_at = source.get("mounted_at") if source else None
        if not mounted_at:
            return self._make_result(
                ValidatorVerdict.NOT_APPLICABLE,
                f"Evidence source {anchor.source_id} not found or not mounted.",
            )

        # Try the original path plus known prefix variations.
        for candidate, prefix_note in self._candidates(artifact_path):
            resolved, strategy = self._try_resolve(candidate, mounted_at)
            if resolved is not None:
                notes = [n for n in (prefix_note, strategy) if n]
                via = f" ({', '.join(notes)})" if notes else ""
                return self._make_result(
                    ValidatorVerdict.PASS,
                    f"Artifact verified at {resolved}{via}.",
                )

        return self._make_result(
            ValidatorVerdict.FAIL_SOFT,
            f"Path unresolved: '{artifact_path}' not found at expected location "
            f"under {mounted_at}. Attempted: direct resolution, case-insensitive "
            f"match, Windows prefix normalization. This may indicate a naming "
            f"variant, deleted file, or hallucinated path. Finding remains at "
            f"current status with 'path_unresolved' flag recommended.",
        )

    # --- candidate generation ---

    def _candidates(self, artifact_path: str):
        """Yield (candidate_path, prefix_note) pairs to attempt, original first."""
        seen = set()

        def emit(path, note):
            if path and path not in seen:
                seen.add(path)
                return [(path, note)]
            return []

        results = emit(artifact_path, "")

        # \Device\HarddiskVolumeN\remainder
        if _HARDDISK_VOLUME_RE.match(artifact_path):
            remainder = _HARDDISK_VOLUME_RE.sub("", artifact_path)
            results += emit(remainder, "stripped \\Device\\HarddiskVolume prefix")

        # \\?\C:\remainder  or  \??\C:\remainder
        m = _EXTENDED_DRIVE_RE.match(artifact_path)
        if m:
            remainder = artifact_path[m.end():]
            results += emit(remainder, "stripped extended-length drive prefix")

        # \SystemRoot\remainder -> Windows\remainder
        if _SYSTEMROOT_RE.match(artifact_path):
            remainder = "Windows\\" + _SYSTEMROOT_RE.sub("", artifact_path)
            results += emit(remainder, "expanded \\SystemRoot to Windows")

        return results

    # --- resolution strategies ---

    def _try_resolve(self, artifact_path: str, mounted_at: str):
        """Return (resolved_path, strategy_note) or (None, None) for one candidate."""
        rel = self._to_relative(artifact_path)
        if rel is None:
            return None, None

        # Strategy A — direct resolution.
        direct = os.path.normpath(os.path.join(mounted_at, rel))
        try:
            if os.path.exists(direct):
                return direct, "direct resolution"
        except (OSError, ValueError):
            pass

        # Strategy B — case-insensitive match within an existing directory.
        ci = self._case_insensitive_resolve(mounted_at, rel)
        if ci is not None:
            return ci, "resolved via case-insensitive match"

        return None, None

    @staticmethod
    def _to_relative(artifact_path: str) -> str | None:
        """Normalize an artifact path to a slash-delimited path relative to the mount."""
        path = artifact_path
        # Strip a leading drive letter (C:\ -> ).
        path = _DRIVE_LETTER_RE.sub("", path, count=1)
        if "\\" in path:
            path = path.replace("\\", "/")
        # Strip any leading slashes so it joins cleanly under mounted_at.
        rel = path.lstrip("/")
        return rel if rel else None

    @staticmethod
    def _case_insensitive_resolve(mounted_at: str, rel: str) -> str | None:
        """Walk the relative path component-by-component, matching case-insensitively."""
        current = mounted_at
        try:
            if not os.path.isdir(current):
                return None
            for component in [c for c in rel.split("/") if c]:
                entries = os.listdir(current)
                match = None
                lowered = component.lower()
                for entry in entries:
                    if entry.lower() == lowered:
                        match = entry
                        break
                if match is None:
                    return None
                current = os.path.join(current, match)
            return current
        except (PermissionError, OSError, ValueError):
            return None

    @staticmethod
    def _find_source(source_id: str, context: dict) -> dict | None:
        for source in context.get("evidence_sources", []) or []:
            if source.get("source_id") == source_id:
                return source
        return None
