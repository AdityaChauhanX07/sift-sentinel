"""Tool output fidelity validator — the highest-value hallucination catcher.

Checks whether the concrete entities a finding claims (filenames, hashes, PIDs,
IPs, registry paths) actually appear in the raw tool output the finding
references. Matching is field-aware against normalized values, not naive string
comparison.

HARD failure only on *categorical absence* — every extracted claim is absent
from the output in any form, meaning the finding appears wholly fabricated.
Format mismatches (separators, case) and partial matches degrade to SOFT.
"""

from __future__ import annotations

import json
import os
import re

from .base import BaseValidator, ValidatorVerdict
from ..evidence_graph.models import Finding


_PID_RE = re.compile(r"\bPID\s*[:=]?\s*(\d+)\b", re.IGNORECASE)
_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_REGISTRY_RE = re.compile(r"(HK[A-Z_]+\\[^\s,;]+)")


class ToolOutputFidelityValidator(BaseValidator):
    """Verifies finding claims are present in the referenced raw tool output."""

    @property
    def name(self) -> str:
        """Identifier used as ValidationResult.validator_name."""
        return "tool_output_fidelity"

    @property
    def description(self) -> str:
        """One-line description of the check."""
        return (
            "Checks whether finding claims are present in the referenced tool "
            "output — field-aware matching"
        )

    # --- claim extraction ---

    def _extract_claims(self, finding: Finding) -> list[dict]:
        """Extract verifiable {type, value, source} claims from a finding."""
        claims: list[dict] = []
        anchor = finding.evidence_anchor

        if anchor is not None:
            if anchor.artifact_path:
                filename = self._basename(anchor.artifact_path)
                if filename:
                    claims.append(
                        {
                            "type": "filename",
                            "value": filename,
                            "source": "evidence_anchor.artifact_path",
                        }
                    )
                claims.append(
                    {
                        "type": "path",
                        "value": anchor.artifact_path,
                        "source": "evidence_anchor.artifact_path",
                    }
                )

            if anchor.file_hash:
                cleaned = anchor.file_hash.strip().lower()
                for prefix in ("sha256:", "md5:"):
                    if cleaned.startswith(prefix):
                        cleaned = cleaned[len(prefix):]
                        break
                if cleaned:
                    claims.append(
                        {
                            "type": "hash",
                            "value": cleaned,
                            "source": "evidence_anchor.file_hash",
                        }
                    )

        summary = finding.summary or ""
        for match in _PID_RE.finditer(summary):
            claims.append({"type": "pid", "value": match.group(1), "source": "summary"})
        for match in _IP_RE.finditer(summary):
            claims.append(
                {"type": "ip_address", "value": match.group(1), "source": "summary"}
            )
        for match in _REGISTRY_RE.finditer(summary):
            claims.append(
                {"type": "registry_path", "value": match.group(1), "source": "summary"}
            )

        return claims

    @staticmethod
    def _basename(path: str) -> str:
        """Return the last path component, splitting on both / and \\."""
        return re.split(r"[\\/]", path)[-1]

    # --- per-claim checking ---

    def _check_claim_in_output(
        self, claim: dict, raw_output: str, normalized_output: str | None
    ) -> dict:
        """Check one claim against the output; returns match metadata dict."""
        ctype = claim.get("type")
        value = claim.get("value", "")
        raw_lower = raw_output.lower()
        value_lower = value.lower()

        def result(found, match_type, detail):
            return {
                "claim": claim,
                "found": found,
                "match_type": match_type,
                "detail": detail,
            }

        if ctype == "filename":
            if value in raw_output:
                return result(True, "exact", f"Filename '{value}' found in output.")
            if value_lower in raw_lower:
                return result(
                    True, "normalized", f"Filename '{value}' found (case-insensitive)."
                )
            return result(False, "not_found", f"Filename '{value}' not in output.")

        if ctype == "path":
            if value in raw_output:
                return result(True, "exact", f"Path '{value}' found in output.")
            swapped = (
                value.replace("\\", "/") if "\\" in value else value.replace("/", "\\")
            )
            if swapped in raw_output:
                return result(
                    True, "normalized", f"Path '{value}' found with swapped separators."
                )
            filename = self._basename(value)
            if filename and filename.lower() in raw_lower:
                return result(
                    True, "partial", f"Path absent but filename '{filename}' present."
                )
            return result(False, "not_found", f"Path '{value}' not in output.")

        if ctype == "hash":
            if value_lower in raw_lower:
                return result(True, "exact", f"Hash '{value[:12]}...' found in output.")
            return result(False, "not_found", f"Hash '{value[:12]}...' not in output.")

        if ctype == "pid":
            if re.search(r"\b" + re.escape(value) + r"\b", raw_output):
                return result(True, "exact", f"PID {value} found in output.")
            return result(False, "not_found", f"PID {value} not in output.")

        if ctype == "ip_address":
            if value in raw_output:
                return result(True, "exact", f"IP {value} found in output.")
            return result(False, "not_found", f"IP {value} not in output.")

        if ctype == "registry_path":
            if value_lower in raw_lower:
                return result(True, "exact", f"Registry path '{value}' found in output.")
            if value.replace("\\", "/").lower() in raw_lower:
                return result(
                    True, "normalized", f"Registry path '{value}' found with / separators."
                )
            last_key = self._basename(value)
            if last_key and last_key.lower() in raw_lower:
                return result(
                    True, "partial", f"Registry path absent but key '{last_key}' present."
                )
            return result(False, "not_found", f"Registry path '{value}' not in output.")

        return result(True, "skipped", "Unrecognized claim type")

    # --- validate ---

    def validate(self, finding: Finding, context: dict):
        """Return a ValidationResult assessing claim presence in tool output."""
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

        execution_id = anchor.tool_execution_id
        if not execution_id:
            return self._make_result(
                ValidatorVerdict.NOT_APPLICABLE, "No tool execution ID referenced."
            )

        raw_output = self._load_raw_output(execution_id, context)
        if raw_output is None:
            return self._make_result(
                ValidatorVerdict.NOT_APPLICABLE,
                f"Raw output for execution {execution_id} not available.",
            )

        normalized_outputs = context.get("normalized_outputs") or {}
        normalized_output = normalized_outputs.get(execution_id)

        claims = self._extract_claims(finding)
        if not claims:
            return self._make_result(
                ValidatorVerdict.NOT_APPLICABLE,
                "No verifiable claims could be extracted from this finding.",
            )

        checks = [
            self._check_claim_in_output(c, raw_output, normalized_output) for c in claims
        ]

        total = len(checks)
        not_found = [c for c in checks if c["match_type"] == "not_found"]
        exact = [c for c in checks if c["match_type"] == "exact"]
        normalized = [c for c in checks if c["match_type"] == "normalized"]
        partial = [c for c in checks if c["match_type"] == "partial"]
        found_count = total - len(not_found)

        # Categorical absence — every claim missing in every form.
        if len(not_found) == total:
            listed = "; ".join(
                f"{c['claim']['type']}={c['claim']['value']}" for c in checks
            )
            return self._make_result(
                ValidatorVerdict.FAIL_HARD,
                f"CATEGORICAL ABSENCE — none of the {total} extracted claims "
                f"(filenames, hashes, PIDs) appear in any form in the tool output "
                f"for execution {execution_id}. The agent's finding appears to be "
                f"entirely fabricated. Claims checked: {listed}.",
            )

        # Some missing, some present.
        if not_found:
            missing = "; ".join(
                f"{c['claim']['type']}={c['claim']['value']}" for c in not_found
            )
            return self._make_result(
                ValidatorVerdict.FAIL_SOFT,
                f"Partial match — {found_count}/{total} claims verified in tool "
                f"output. Missing: {missing}. Present claims may have format "
                f"differences. Recommend manual review.",
            )

        # All found.
        if len(exact) == total:
            return self._make_result(
                ValidatorVerdict.PASS,
                f"All {total} claims verified in tool output (exact matches).",
            )

        return self._make_result(
            ValidatorVerdict.PASS,
            f"All {total} claims present in tool output ({len(exact)} exact, "
            f"{len(normalized)} normalized format, {len(partial)} partial matches).",
        )

    # --- helpers ---

    @staticmethod
    def _load_raw_output(execution_id: str, context: dict) -> str | None:
        raw_outputs = context.get("raw_outputs") or {}
        if execution_id in raw_outputs:
            return raw_outputs[execution_id]

        raw_paths = context.get("raw_output_paths") or {}
        path = raw_paths.get(execution_id)
        if path and os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    return fh.read()
            except (OSError, ValueError):
                return None
        return None
