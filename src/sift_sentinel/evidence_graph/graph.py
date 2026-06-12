"""CRUD operations and status lifecycle logic for the evidence graph.

``EvidenceGraphManager`` wraps a single :class:`EvidenceGraph` instance and is
the only sanctioned way to mutate it. Findings always enter the graph
ungated; validation and lifecycle transitions happen through explicit calls.
"""

from __future__ import annotations

import datetime
import json
import os

from .models import (
    Contradiction,
    CorroborationType,
    EvidenceAnchor,
    EvidenceGraph,
    EvidenceSource,
    Finding,
    FindingStatus,
    InvestigationTask,
    PromotionRecord,
    ReasoningChain,
    ValidationResult,
)


class EvidenceGraphManager:
    """Stateful manager providing CRUD and lifecycle operations over an EvidenceGraph."""

    def __init__(self, case_id: str):
        """Create a fresh evidence graph for the given case and stamp the start time."""
        self.graph = EvidenceGraph(case_id=case_id)
        self.graph.metadata.analysis_start = self._now()
        self._finding_counter = 0
        self._contradiction_counter = 0
        self._task_counter = 0

    def _now(self) -> str:
        """Return the current UTC time as an ISO 8601 string."""
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

    # --- EVIDENCE SOURCE MANAGEMENT ---

    def add_source(
        self,
        source_type: str,
        path: str,
        sha256: str,
        mounted_at: str,
        metadata: dict | None = None,
    ) -> EvidenceSource:
        """Register a new evidence source with an auto-generated source id."""
        source_id = f"src-{len(self.graph.evidence_sources) + 1:03d}"
        source = EvidenceSource(
            source_id=source_id,
            source_type=source_type,
            path=path,
            sha256=sha256,
            mounted_at=mounted_at,
            metadata=metadata if metadata is not None else {},
        )
        self.graph.evidence_sources.append(source)
        return source

    # --- FINDING MANAGEMENT ---

    def add_finding(
        self,
        summary: str,
        category: str,
        evidence_anchor: EvidenceAnchor,
        status: FindingStatus = FindingStatus.HYPOTHESIS,
        mitre_attack: list[str] | None = None,
    ) -> Finding:
        """Add a finding to the graph ungated; returns the created Finding."""
        self._finding_counter += 1
        finding_id = f"F-{self._finding_counter:03d}"
        now = self._now()
        finding = Finding(
            finding_id=finding_id,
            status=status,
            category=category,
            summary=summary,
            evidence_anchor=evidence_anchor,
            mitre_attack=mitre_attack if mitre_attack is not None else [],
            created_at=now,
            last_updated=now,
        )
        self.graph.findings.append(finding)
        return finding

    def get_finding(self, finding_id: str) -> Finding | None:
        """Return the finding with the given id, or None if absent."""
        for finding in self.graph.findings:
            if finding.finding_id == finding_id:
                return finding
        return None

    def get_findings_by_status(self, status: FindingStatus) -> list[Finding]:
        """Return all findings currently in the given status."""
        return [f for f in self.graph.findings if f.status == status]

    # --- STATUS LIFECYCLE ---

    def promote_finding(
        self, finding_id: str, to_status: FindingStatus, reason: str, triggered_by: str
    ) -> bool:
        """Promote a finding upward through the lifecycle; raises ValueError if illegal."""
        finding = self.get_finding(finding_id)
        if finding is None:
            return False

        current = finding.status
        legal = (
            (current == FindingStatus.HYPOTHESIS and to_status == FindingStatus.INFERRED)
            or (current == FindingStatus.HYPOTHESIS and to_status == FindingStatus.CONFIRMED)
            or (current == FindingStatus.INFERRED and to_status == FindingStatus.CONFIRMED)
            or (to_status == FindingStatus.ELIMINATED)
        )
        if not legal:
            raise ValueError(
                f"Illegal promotion for {finding_id}: "
                f"{current.value} -> {to_status.value}"
            )

        if to_status in (FindingStatus.INFERRED, FindingStatus.CONFIRMED):
            if finding.evidence_anchor is None:
                raise ValueError(
                    f"Cannot promote {finding_id} to {to_status.value}: "
                    f"finding has no evidence_anchor"
                )

        now = self._now()
        finding.promotion_history.append(
            PromotionRecord(
                from_status=current,
                to_status=to_status,
                reason=reason,
                triggered_by=triggered_by,
                timestamp=now,
            )
        )
        finding.status = to_status
        finding.last_updated = now
        return True

    def demote_finding(
        self, finding_id: str, to_status: FindingStatus, reason: str, triggered_by: str
    ) -> bool:
        """Demote a finding downward through the lifecycle; raises ValueError if illegal."""
        finding = self.get_finding(finding_id)
        if finding is None:
            return False

        current = finding.status
        legal = (
            (current == FindingStatus.CONFIRMED and to_status == FindingStatus.INFERRED)
            or (current == FindingStatus.CONFIRMED and to_status == FindingStatus.HYPOTHESIS)
            or (current == FindingStatus.INFERRED and to_status == FindingStatus.HYPOTHESIS)
            or (to_status == FindingStatus.ELIMINATED)
        )
        if not legal:
            raise ValueError(
                f"Illegal demotion for {finding_id}: "
                f"{current.value} -> {to_status.value}"
            )

        now = self._now()
        finding.promotion_history.append(
            PromotionRecord(
                from_status=current,
                to_status=to_status,
                reason=reason,
                triggered_by=triggered_by,
                timestamp=now,
            )
        )
        finding.status = to_status
        finding.last_updated = now
        return True

    def eliminate_finding(self, finding_id: str, reason: str, triggered_by: str) -> bool:
        """Eliminate a finding from any status; elimination is always legal."""
        finding = self.get_finding(finding_id)
        if finding is None:
            return False

        now = self._now()
        finding.promotion_history.append(
            PromotionRecord(
                from_status=finding.status,
                to_status=FindingStatus.ELIMINATED,
                reason=reason,
                triggered_by=triggered_by,
                timestamp=now,
            )
        )
        finding.status = FindingStatus.ELIMINATED
        finding.last_updated = now
        return True

    # --- FLAG MANAGEMENT ---

    def add_flag(self, finding_id: str, flag: str) -> bool:
        """Add a soft-failure flag to a finding, avoiding duplicates."""
        finding = self.get_finding(finding_id)
        if finding is None or flag in finding.flags:
            return False
        finding.flags.append(flag)
        finding.last_updated = self._now()
        return True

    def remove_flag(self, finding_id: str, flag: str) -> bool:
        """Remove a flag from a finding; returns False if absent."""
        finding = self.get_finding(finding_id)
        if finding is None or flag not in finding.flags:
            return False
        finding.flags.remove(flag)
        finding.last_updated = self._now()
        return True

    def has_flags(self, finding_id: str) -> bool:
        """Return True if the finding exists and carries at least one flag."""
        finding = self.get_finding(finding_id)
        if finding is None:
            return False
        return len(finding.flags) > 0

    # --- VALIDATION RESULTS ---

    def add_validation_result(self, finding_id: str, result: ValidationResult) -> bool:
        """Attach a validation result to a finding."""
        finding = self.get_finding(finding_id)
        if finding is None:
            return False
        finding.validation_results.append(result)
        finding.last_updated = self._now()
        return True

    # --- REASONING CHAIN ---

    def set_reasoning_chain(
        self,
        finding_id: str,
        premises: list[str],
        logic: str,
        corroboration_type: CorroborationType,
    ) -> bool:
        """Set and mark-rendered a finding's reasoning chain."""
        finding = self.get_finding(finding_id)
        if finding is None:
            return False
        finding.reasoning_chain = ReasoningChain(
            premises=list(premises),
            logic=logic,
            corroboration_type=corroboration_type,
            chain_rendered=True,
        )
        finding.last_updated = self._now()
        return True

    # --- CONTRADICTION MANAGEMENT ---

    def add_contradiction(
        self,
        finding_a: str,
        finding_b: str,
        description: str,
        follow_up_tasks: list[str] | None = None,
    ) -> Contradiction:
        """Record a contradiction between two findings and cross-link them."""
        self._contradiction_counter += 1
        contradiction_id = f"C-{self._contradiction_counter:03d}"
        contradiction = Contradiction(
            contradiction_id=contradiction_id,
            finding_a=finding_a,
            finding_b=finding_b,
            description=description,
            follow_up_tasks=follow_up_tasks if follow_up_tasks is not None else [],
            status="OPEN",
        )
        for fid in (finding_a, finding_b):
            finding = self.get_finding(fid)
            if finding is not None and contradiction_id not in finding.contradictions:
                finding.contradictions.append(contradiction_id)
        self.graph.contradictions.append(contradiction)
        return contradiction

    def resolve_contradiction(self, contradiction_id: str, resolution: str) -> bool:
        """Mark a contradiction resolved with the supplied resolution text."""
        for contradiction in self.graph.contradictions:
            if contradiction.contradiction_id == contradiction_id:
                contradiction.resolution = resolution
                contradiction.status = "RESOLVED"
                return True
        return False

    # --- INVESTIGATION QUEUE ---

    def add_task(
        self, description: str, triggered_by: str, priority: str = "MEDIUM"
    ) -> InvestigationTask:
        """Queue a new investigation task with an auto-generated task id."""
        self._task_counter += 1
        task_id = f"T-{self._task_counter:03d}"
        task = InvestigationTask(
            task_id=task_id,
            description=description,
            triggered_by=triggered_by,
            priority=priority,
        )
        self.graph.investigation_queue.append(task)
        return task

    def update_task_status(
        self, task_id: str, status: str, result_finding_ids: list[str] | None = None
    ) -> bool:
        """Update a task's status and optionally record produced finding ids."""
        for task in self.graph.investigation_queue:
            if task.task_id == task_id:
                task.status = status
                if result_finding_ids is not None:
                    task.result_finding_ids.extend(result_finding_ids)
                return True
        return False

    def get_pending_tasks(self, priority: str | None = None) -> list[InvestigationTask]:
        """Return pending tasks, optionally filtered to a single priority."""
        return [
            t
            for t in self.graph.investigation_queue
            if t.status == "PENDING" and (priority is None or t.priority == priority)
        ]

    # --- STATISTICS ---

    def get_status_breakdown(self) -> dict[str, int]:
        """Return a count of findings by status value."""
        breakdown: dict[str, int] = {}
        for finding in self.graph.findings:
            key = finding.status.value
            breakdown[key] = breakdown.get(key, 0) + 1
        return breakdown

    def get_summary(self) -> dict:
        """Return a high-level summary of the current graph state."""
        return {
            "case_id": self.graph.case_id,
            "total_findings": len(self.graph.findings),
            "status_breakdown": self.get_status_breakdown(),
            "open_contradictions": sum(
                1 for c in self.graph.contradictions if c.status == "OPEN"
            ),
            "pending_tasks": sum(
                1 for t in self.graph.investigation_queue if t.status == "PENDING"
            ),
            "total_tool_executions": self.graph.metadata.total_tool_executions,
            "analysis_start": self.graph.metadata.analysis_start,
            "flagged_findings": sum(
                1 for f in self.graph.findings if len(f.flags) > 0
            ),
        }

    # --- PERSISTENCE ---

    def save(self, filepath: str) -> None:
        """Serialize the graph to a JSON file, creating parent directories as needed."""
        parent = os.path.dirname(filepath)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(self.graph.to_dict(), fh, indent=2)

    def save_snapshot(self, snapshot_dir: str, label: str) -> str:
        """Write a labeled snapshot of the graph and return its filepath."""
        filepath = os.path.join(snapshot_dir, f"graph_{label}.json")
        self.save(filepath)
        return filepath

    @classmethod
    def load(cls, filepath: str) -> "EvidenceGraphManager":
        """Load a manager from a serialized graph, restoring internal counters."""
        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        graph = EvidenceGraph.from_dict(data)
        manager = cls(graph.case_id)
        manager.graph = graph
        manager._finding_counter = len(graph.findings)
        manager._contradiction_counter = len(graph.contradictions)
        manager._task_counter = len(graph.investigation_queue)
        return manager
