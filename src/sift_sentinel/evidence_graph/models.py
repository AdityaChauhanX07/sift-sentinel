"""Evidence graph data models for SIFT Sentinel.

Pure standard-library dataclasses defining the schema for the evidence graph.
Every model supports JSON round-tripping via ``to_dict`` / ``from_dict``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class FindingStatus(str, Enum):
    HYPOTHESIS = "HYPOTHESIS"
    INFERRED = "INFERRED"
    CONFIRMED = "CONFIRMED"
    ELIMINATED = "ELIMINATED"


class CorroborationType(str, Enum):
    # multiple independent artifact types agree
    INDEPENDENT_SOURCES = "independent_sources"
    # one artifact with supporting context from another
    SINGLE_SOURCE_CORROBORATED = "single_source_corroborated"
    # one artifact, agent constructed causal interpretation
    SINGLE_SOURCE_NARRATED = "single_source_narrated"
    # for HYPOTHESIS and CONFIRMED findings that don't need a reasoning chain
    NOT_APPLICABLE = "not_applicable"


class ValidatorVerdict(str, Enum):
    PASS = "PASS"
    # logical impossibility, triggers ELIMINATED
    FAIL_HARD = "FAIL_HARD"
    # inconclusive, flags finding for review
    FAIL_SOFT = "FAIL_SOFT"
    # validator doesn't apply to this finding type
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class EvidenceSource:
    source_id: str
    source_type: str
    path: str
    sha256: str
    mounted_at: str
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "source_id": self.source_id,
            "source_type": self.source_type,
            "path": self.path,
            "sha256": self.sha256,
            "mounted_at": self.mounted_at,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EvidenceSource":
        return cls(
            source_id=data["source_id"],
            source_type=data["source_type"],
            path=data["path"],
            sha256=data["sha256"],
            mounted_at=data["mounted_at"],
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class EvidenceAnchor:
    source_id: str
    tool_execution_id: str
    artifact_path: str | None = None
    file_hash: str | None = None
    offset: str | None = None
    log_entry: str | None = None
    raw_output_reference: str | None = None

    def __post_init__(self) -> None:
        if self.artifact_path is None and self.offset is None and self.log_entry is None:
            raise ValueError(
                "EvidenceAnchor requires at least one concrete reference: "
                "artifact_path, offset, or log_entry must be set"
            )

    def to_dict(self) -> dict:
        return {
            "source_id": self.source_id,
            "tool_execution_id": self.tool_execution_id,
            "artifact_path": self.artifact_path,
            "file_hash": self.file_hash,
            "offset": self.offset,
            "log_entry": self.log_entry,
            "raw_output_reference": self.raw_output_reference,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EvidenceAnchor":
        return cls(
            source_id=data["source_id"],
            tool_execution_id=data["tool_execution_id"],
            artifact_path=data.get("artifact_path"),
            file_hash=data.get("file_hash"),
            offset=data.get("offset"),
            log_entry=data.get("log_entry"),
            raw_output_reference=data.get("raw_output_reference"),
        )


@dataclass
class ValidationResult:
    validator_name: str
    verdict: ValidatorVerdict
    detail: str
    timestamp: str

    def to_dict(self) -> dict:
        return {
            "validator_name": self.validator_name,
            "verdict": self.verdict.value,
            "detail": self.detail,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ValidationResult":
        return cls(
            validator_name=data["validator_name"],
            verdict=ValidatorVerdict(data["verdict"]),
            detail=data["detail"],
            timestamp=data["timestamp"],
        )


@dataclass
class PromotionRecord:
    from_status: FindingStatus
    to_status: FindingStatus
    reason: str
    triggered_by: str
    timestamp: str

    def to_dict(self) -> dict:
        return {
            "from_status": self.from_status.value,
            "to_status": self.to_status.value,
            "reason": self.reason,
            "triggered_by": self.triggered_by,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PromotionRecord":
        return cls(
            from_status=FindingStatus(data["from_status"]),
            to_status=FindingStatus(data["to_status"]),
            reason=data["reason"],
            triggered_by=data["triggered_by"],
            timestamp=data["timestamp"],
        )


@dataclass
class ReasoningChain:
    premises: list[str] = field(default_factory=list)
    logic: str = ""
    corroboration_type: CorroborationType = CorroborationType.NOT_APPLICABLE
    chain_rendered: bool = False

    def to_dict(self) -> dict:
        return {
            "premises": list(self.premises),
            "logic": self.logic,
            "corroboration_type": self.corroboration_type.value,
            "chain_rendered": self.chain_rendered,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ReasoningChain":
        return cls(
            premises=list(data.get("premises", [])),
            logic=data.get("logic", ""),
            corroboration_type=CorroborationType(
                data.get("corroboration_type", CorroborationType.NOT_APPLICABLE.value)
            ),
            chain_rendered=data.get("chain_rendered", False),
        )


@dataclass
class Finding:
    finding_id: str
    status: FindingStatus = FindingStatus.HYPOTHESIS
    category: str = ""
    summary: str = ""
    evidence_anchor: EvidenceAnchor | None = None
    reasoning_chain: ReasoningChain = field(default_factory=ReasoningChain)
    mitre_attack: list[str] = field(default_factory=list)
    linked_findings: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    validation_results: list[ValidationResult] = field(default_factory=list)
    promotion_history: list[PromotionRecord] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    created_at: str = ""
    last_updated: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "status": self.status.value,
            "category": self.category,
            "summary": self.summary,
            "evidence_anchor": (
                self.evidence_anchor.to_dict()
                if self.evidence_anchor is not None
                else None
            ),
            "reasoning_chain": self.reasoning_chain.to_dict(),
            "mitre_attack": list(self.mitre_attack),
            "linked_findings": list(self.linked_findings),
            "contradictions": list(self.contradictions),
            "validation_results": [v.to_dict() for v in self.validation_results],
            "promotion_history": [p.to_dict() for p in self.promotion_history],
            "flags": list(self.flags),
            "created_at": self.created_at,
            "last_updated": self.last_updated,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        anchor = data.get("evidence_anchor")
        reasoning = data.get("reasoning_chain")
        return cls(
            finding_id=data["finding_id"],
            status=FindingStatus(data.get("status", FindingStatus.HYPOTHESIS.value)),
            category=data.get("category", ""),
            summary=data.get("summary", ""),
            evidence_anchor=(
                EvidenceAnchor.from_dict(anchor) if anchor is not None else None
            ),
            reasoning_chain=(
                ReasoningChain.from_dict(reasoning)
                if reasoning is not None
                else ReasoningChain()
            ),
            mitre_attack=list(data.get("mitre_attack", [])),
            linked_findings=list(data.get("linked_findings", [])),
            contradictions=list(data.get("contradictions", [])),
            validation_results=[
                ValidationResult.from_dict(v) for v in data.get("validation_results", [])
            ],
            promotion_history=[
                PromotionRecord.from_dict(p) for p in data.get("promotion_history", [])
            ],
            flags=list(data.get("flags", [])),
            created_at=data.get("created_at", ""),
            last_updated=data.get("last_updated", ""),
        )


@dataclass
class Contradiction:
    contradiction_id: str
    finding_a: str
    finding_b: str
    description: str
    resolution: str | None = None
    follow_up_tasks: list[str] = field(default_factory=list)
    status: str = "OPEN"

    def to_dict(self) -> dict:
        return {
            "contradiction_id": self.contradiction_id,
            "finding_a": self.finding_a,
            "finding_b": self.finding_b,
            "description": self.description,
            "resolution": self.resolution,
            "follow_up_tasks": list(self.follow_up_tasks),
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Contradiction":
        return cls(
            contradiction_id=data["contradiction_id"],
            finding_a=data["finding_a"],
            finding_b=data["finding_b"],
            description=data["description"],
            resolution=data.get("resolution"),
            follow_up_tasks=list(data.get("follow_up_tasks", [])),
            status=data.get("status", "OPEN"),
        )


@dataclass
class InvestigationTask:
    task_id: str
    description: str
    triggered_by: str
    priority: str = "MEDIUM"
    status: str = "PENDING"
    result_finding_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "description": self.description,
            "triggered_by": self.triggered_by,
            "priority": self.priority,
            "status": self.status,
            "result_finding_ids": list(self.result_finding_ids),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "InvestigationTask":
        return cls(
            task_id=data["task_id"],
            description=data["description"],
            triggered_by=data["triggered_by"],
            priority=data.get("priority", "MEDIUM"),
            status=data.get("status", "PENDING"),
            result_finding_ids=list(data.get("result_finding_ids", [])),
        )


@dataclass
class EvidenceGraphMetadata:
    agent_version: str = "0.1.0"
    total_tool_executions: int = 0
    analysis_start: str = ""
    analysis_end: str = ""

    def to_dict(self) -> dict:
        return {
            "agent_version": self.agent_version,
            "total_tool_executions": self.total_tool_executions,
            "analysis_start": self.analysis_start,
            "analysis_end": self.analysis_end,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EvidenceGraphMetadata":
        return cls(
            agent_version=data.get("agent_version", "0.1.0"),
            total_tool_executions=data.get("total_tool_executions", 0),
            analysis_start=data.get("analysis_start", ""),
            analysis_end=data.get("analysis_end", ""),
        )


@dataclass
class EvidenceGraph:
    case_id: str = ""
    evidence_sources: list[EvidenceSource] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    contradictions: list[Contradiction] = field(default_factory=list)
    investigation_queue: list[InvestigationTask] = field(default_factory=list)
    metadata: EvidenceGraphMetadata = field(default_factory=EvidenceGraphMetadata)

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "evidence_sources": [s.to_dict() for s in self.evidence_sources],
            "findings": [f.to_dict() for f in self.findings],
            "contradictions": [c.to_dict() for c in self.contradictions],
            "investigation_queue": [t.to_dict() for t in self.investigation_queue],
            "metadata": self.metadata.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EvidenceGraph":
        metadata = data.get("metadata")
        return cls(
            case_id=data.get("case_id", ""),
            evidence_sources=[
                EvidenceSource.from_dict(s) for s in data.get("evidence_sources", [])
            ],
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            contradictions=[
                Contradiction.from_dict(c) for c in data.get("contradictions", [])
            ],
            investigation_queue=[
                InvestigationTask.from_dict(t)
                for t in data.get("investigation_queue", [])
            ],
            metadata=(
                EvidenceGraphMetadata.from_dict(metadata)
                if metadata is not None
                else EvidenceGraphMetadata()
            ),
        )
