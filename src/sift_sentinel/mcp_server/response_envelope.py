"""Standardized response envelope for MCP tool executions.

Every tool returns its results wrapped in a :class:`ToolResponse`. Raw output
is always persisted to disk and hashed so the audit trail is independent of the
parsed view. Evidence content is treated as structured data — never
concatenated into prompts or interpreted as instructions.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
from dataclasses import dataclass


@dataclass
class ToolResponse:
    """Standardized response envelope for all MCP tool executions.

    The raw output is always preserved separately for audit trail purposes.
    Evidence content is parsed as structured data — never concatenated into
    prompts or interpreted as instructions.
    """

    tool: str
    execution_id: str
    timestamp: str
    input_params: dict
    status: str
    raw_output_hash: str
    raw_output_path: str
    parsed_output: list | dict | None
    normalized_fields: dict
    evidence_integrity_check: dict
    error_message: str = ""
    duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        """Return a JSON-serializable dict of the response."""
        return {
            "tool": self.tool,
            "execution_id": self.execution_id,
            "timestamp": self.timestamp,
            "input_params": dict(self.input_params),
            "status": self.status,
            "raw_output_hash": self.raw_output_hash,
            "raw_output_path": self.raw_output_path,
            "parsed_output": self.parsed_output,
            "normalized_fields": dict(self.normalized_fields),
            "evidence_integrity_check": dict(self.evidence_integrity_check),
            "error_message": self.error_message,
            "duration_seconds": self.duration_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ToolResponse":
        """Reconstruct a ToolResponse from a dict (inverse of to_dict)."""
        return cls(
            tool=data["tool"],
            execution_id=data["execution_id"],
            timestamp=data["timestamp"],
            input_params=dict(data.get("input_params", {})),
            status=data["status"],
            raw_output_hash=data["raw_output_hash"],
            raw_output_path=data["raw_output_path"],
            parsed_output=data.get("parsed_output"),
            normalized_fields=dict(data.get("normalized_fields", {})),
            evidence_integrity_check=dict(data.get("evidence_integrity_check", {})),
            error_message=data.get("error_message", ""),
            duration_seconds=data.get("duration_seconds", 0.0),
        )


def create_response(
    tool: str,
    execution_id: str,
    input_params: dict,
    status: str,
    raw_output: str,
    raw_output_dir: str,
    parsed_output: list | dict | None,
    evidence_hashes: dict | None = None,
    normalized_fields: dict | None = None,
    error_message: str = "",
    duration_seconds: float = 0.0,
) -> ToolResponse:
    """Create a ToolResponse, persisting and hashing the raw output.

    Saves ``raw_output`` to ``{raw_output_dir}/{execution_id}.txt``, computes
    the SHA-256 of its bytes, builds the integrity check from
    ``evidence_hashes`` (or a not-checked placeholder), and returns the
    assembled :class:`ToolResponse`.
    """
    os.makedirs(raw_output_dir, exist_ok=True)
    raw_output_path = os.path.join(raw_output_dir, f"{execution_id}.txt")
    with open(raw_output_path, "w", encoding="utf-8") as fh:
        fh.write(raw_output)

    raw_output_hash = "sha256:" + hashlib.sha256(
        raw_output.encode("utf-8")
    ).hexdigest()

    if evidence_hashes is not None:
        evidence_integrity_check = {
            "pre_hash": evidence_hashes.get("pre_hash"),
            "post_hash": evidence_hashes.get("post_hash"),
            "match": evidence_hashes.get("match"),
        }
    else:
        evidence_integrity_check = {
            "pre_hash": "not_checked",
            "post_hash": "not_checked",
            "match": True,
        }

    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    return ToolResponse(
        tool=tool,
        execution_id=execution_id,
        timestamp=timestamp,
        input_params=dict(input_params),
        status=status,
        raw_output_hash=raw_output_hash,
        raw_output_path=raw_output_path,
        parsed_output=parsed_output,
        normalized_fields=normalized_fields if normalized_fields is not None else {},
        evidence_integrity_check=evidence_integrity_check,
        error_message=error_message,
        duration_seconds=duration_seconds,
    )


class ExecutionTracker:
    """Generates sequential execution IDs and tracks all tool executions."""

    def __init__(self):
        """Initialize an empty execution counter and log."""
        self._counter = 0
        self._log: list[ToolResponse] = []

    def next_id(self) -> str:
        """Return the next sequential execution id, e.g. 'exec-0001'."""
        self._counter += 1
        return f"exec-{self._counter:04d}"

    def record(self, response: ToolResponse) -> None:
        """Append a ToolResponse to the execution log."""
        self._log.append(response)

    def get_log(self) -> list[ToolResponse]:
        """Return a shallow copy of the execution log."""
        return list(self._log)

    def save_log(self, filepath: str) -> None:
        """Save the full execution log as JSON."""
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump([r.to_dict() for r in self._log], f, indent=2)

    def get_raw_outputs_map(self) -> dict[str, str]:
        """Return a dict mapping execution_id -> raw_output_path for validator context."""
        return {r.execution_id: r.raw_output_path for r in self._log}
