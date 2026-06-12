"""Hash verification validator.

Independently recomputes the SHA-256 of the file at a finding's claimed
artifact path and compares it against the hash claimed in the evidence anchor.
A definitive mismatch on a readable file is the clearest hallucination signal —
the agent asserted a specific hash for a specific file and it's wrong — so that
is a HARD failure. A missing or unreadable file is SOFT (unverifiable). No hash,
no path, a non-SHA-256 hash, or a directory target is NOT_APPLICABLE.
"""

from __future__ import annotations

import hashlib
import os

from .base import BaseValidator, ValidatorVerdict
from ..evidence_graph.models import Finding


class HashVerificationValidator(BaseValidator):
    """Recomputes file hashes and compares them against the claimed hash."""

    @property
    def name(self) -> str:
        """Identifier used as ValidationResult.validator_name."""
        return "hash_verification"

    @property
    def description(self) -> str:
        """One-line description of the check."""
        return "Independently computes file hash and compares against claimed hash"

    @staticmethod
    def _compute_sha256(filepath: str) -> str | None:
        """Return 'sha256:<hexdigest>' for the file, or None on any failure."""
        try:
            digest = hashlib.sha256()
            with open(filepath, "rb") as fh:
                for chunk in iter(lambda: fh.read(8192), b""):
                    digest.update(chunk)
            return "sha256:" + digest.hexdigest()
        except Exception:
            return None

    @staticmethod
    def _normalize_hash(hash_str: str) -> str | None:
        """Return a clean 64-char lowercase SHA-256 hex string, or None if not one."""
        if not isinstance(hash_str, str):
            return None
        cleaned = hash_str.strip().lower()
        if cleaned.startswith("md5:"):
            return None  # different hash type — not comparable
        if cleaned.startswith("sha256:"):
            cleaned = cleaned[len("sha256:"):]
        if not cleaned or any(c not in "0123456789abcdef" for c in cleaned):
            return None
        if len(cleaned) != 64:
            return None
        return cleaned

    def validate(self, finding: Finding, context: dict):
        """Return a ValidationResult comparing the claimed hash to a recomputed one."""
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

        claimed_raw = anchor.file_hash
        if not claimed_raw:
            return self._make_result(
                ValidatorVerdict.NOT_APPLICABLE,
                "No hash claim in evidence anchor — nothing to verify.",
            )

        claimed = self._normalize_hash(claimed_raw)
        if claimed is None:
            return self._make_result(
                ValidatorVerdict.NOT_APPLICABLE,
                f"Cannot verify hash: '{claimed_raw}' is not a recognized "
                f"SHA-256 format.",
            )

        artifact_path = anchor.artifact_path
        if not artifact_path:
            return self._make_result(
                ValidatorVerdict.NOT_APPLICABLE,
                "Hash claimed but no artifact path to verify against — finding "
                "may reference an offset or log entry.",
            )

        source = self._find_source(anchor.source_id, context)
        mounted_at = source.get("mounted_at") if source else None
        if not mounted_at:
            return self._make_result(
                ValidatorVerdict.NOT_APPLICABLE,
                "Evidence source not found or not mounted.",
            )

        resolved = self._resolve(artifact_path, mounted_at)

        if not os.path.exists(resolved):
            return self._make_result(
                ValidatorVerdict.FAIL_SOFT,
                f"Cannot verify hash — file not found at {resolved}. File may be "
                f"deleted. Hash claim '{claimed_raw}' remains unverified.",
            )
        if os.path.isdir(resolved):
            return self._make_result(
                ValidatorVerdict.NOT_APPLICABLE,
                f"Path {resolved} is a directory, not a file — cannot hash.",
            )

        computed_full = self._compute_sha256(resolved)
        if computed_full is None:
            return self._make_result(
                ValidatorVerdict.FAIL_SOFT,
                f"Failed to compute hash for {resolved} — file may be locked or "
                f"unreadable.",
            )

        computed = self._normalize_hash(computed_full)

        if computed == claimed:
            return self._make_result(
                ValidatorVerdict.PASS,
                f"Hash verified — computed SHA-256 matches claimed hash "
                f"({claimed[:12]}...).",
            )

        return self._make_result(
            ValidatorVerdict.FAIL_HARD,
            f"HASH MISMATCH — claimed sha256:{claimed[:12]}... but computed "
            f"sha256:{computed[:12]}... for file at {resolved}. Agent fabricated "
            f"or confused the file hash.",
        )

    # --- helpers ---

    @staticmethod
    def _resolve(artifact_path: str, mounted_at: str) -> str:
        """Normalize a Windows/Unix artifact path to a local path under the mount."""
        path = artifact_path
        looks_windows = "\\" in path or (len(path) >= 2 and path[1] == ":")
        if looks_windows:
            # Strip a leading drive letter (e.g. "C:").
            if len(path) >= 2 and path[1] == ":":
                path = path[2:]
            path = path.replace("\\", "/")
            rel = path.lstrip("/")
            return os.path.normpath(os.path.join(mounted_at, rel))
        if path.startswith("/"):
            return os.path.normpath(os.path.join(mounted_at, path.lstrip("/")))
        return os.path.normpath(os.path.join(mounted_at, path))

    @staticmethod
    def _find_source(source_id: str, context: dict) -> dict | None:
        for source in context.get("evidence_sources", []) or []:
            if source.get("source_id") == source_id:
                return source
        return None
