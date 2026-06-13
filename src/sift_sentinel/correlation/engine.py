"""Correlation engine — orchestrates the six checks and writes results to the graph.

The engine is deliberately thin: it runs the correlation checks, records
contradictions and follow-up tasks in the evidence graph, and links
corroborating findings so the relationship is visible. It makes no analytical
decisions — promotion remains the agent's call.
"""

from __future__ import annotations

from dataclasses import asdict

from .checks import (
    CorrelationResult,
    check_execution_verification,
    check_file_existence,
    check_persistence_verification,
    check_timestamp_consistency,
    check_execution_count,
    check_hash_consistency,
)
from .crosssource import CROSS_SOURCE_CHECKS
from ..evidence_graph.graph import EvidenceGraphManager
from ..evidence_graph.models import FindingStatus


class CorrelationEngine:
    """Runs correlation checks over an evidence graph and records their outcomes."""

    def __init__(self, graph_manager: EvidenceGraphManager):
        """Store the graph manager and register the ordered check functions."""
        self.graph_manager = graph_manager
        self._checks = [
            check_execution_verification,
            check_file_existence,
            check_persistence_verification,
            check_timestamp_consistency,
            check_execution_count,
            check_hash_consistency,
        ]
        self._check_by_name = {
            "execution_verification": check_execution_verification,
            "file_existence": check_file_existence,
            "persistence_verification": check_persistence_verification,
            "timestamp_consistency": check_timestamp_consistency,
            "execution_count": check_execution_count,
            "hash_consistency": check_hash_consistency,
        }

    def _active_findings(self):
        """Return all non-ELIMINATED findings from the graph."""
        return [
            f
            for f in self.graph_manager.graph.findings
            if f.status != FindingStatus.ELIMINATED
        ]

    def run_all_checks(self) -> dict:
        """Run all correlation checks and record contradictions/tasks/links.

        Returns a summary dict with counts, the created contradiction/task ids,
        all results (as dicts), and any per-check errors.
        """
        active_findings = self._active_findings()

        all_results: list[CorrelationResult] = []
        errors: list[str] = []

        for check in self._checks:
            try:
                all_results.extend(check(active_findings))
            except Exception as exc:  # one broken check must not kill the pipeline
                errors.append(f"{check.__name__} raised {type(exc).__name__}: {exc}")

        # Detect multi-source evidence and run cross-source checks if applicable
        source_types = set()
        for source in self.graph_manager.graph.evidence_sources:
            source_types.add(source.source_type)

        has_multi_source = len(source_types) > 1

        if has_multi_source:
            for check_fn in CROSS_SOURCE_CHECKS:
                try:
                    check_results = check_fn(active_findings)
                    all_results.extend(check_results)
                except Exception as e:
                    errors.append(f"Cross-source check {check_fn.__name__} failed: {e}")

        contradictions_created: list[str] = []
        tasks_created: list[str] = []
        contradictions_found = 0
        corroborations_found = 0

        for result in all_results:
            if result.is_contradiction:
                contradictions_found += 1
                contradiction = self.graph_manager.add_contradiction(
                    finding_a=result.finding_a_id,
                    finding_b=result.finding_b_id,
                    description=result.description,
                )
                contradictions_created.append(contradiction.contradiction_id)
                for suggestion in result.follow_up_suggestions:
                    task = self.graph_manager.add_task(
                        description=suggestion,
                        triggered_by=contradiction.contradiction_id,
                        priority=result.severity,
                    )
                    tasks_created.append(task.task_id)
            else:
                corroborations_found += 1
                self._link_findings(result.finding_a_id, result.finding_b_id)

        return {
            "total_checks_run": len(self._checks),
            "contradictions_found": contradictions_found,
            "corroborations_found": corroborations_found,
            "contradictions_created": contradictions_created,
            "tasks_created": tasks_created,
            "results": [asdict(r) for r in all_results],
            "errors": errors,
        }

    def run_single_check(self, check_name: str) -> list[CorrelationResult]:
        """Run a single named check (e.g. 'execution_verification') without writing.

        Raises ValueError if check_name is not recognized.
        """
        check = self._check_by_name.get(check_name)
        if check is None:
            raise ValueError(
                f"Unrecognized check name '{check_name}'. Valid names: "
                f"{', '.join(sorted(self._check_by_name))}"
            )
        return check(self._active_findings())

    def get_corroborations_for_finding(self, finding_id: str) -> list[CorrelationResult]:
        """Run all checks and return corroboration results involving finding_id."""
        active_findings = self._active_findings()
        corroborations: list[CorrelationResult] = []
        for check in self._checks:
            try:
                results = check(active_findings)
            except Exception:
                continue
            for result in results:
                if not result.is_contradiction and finding_id in (
                    result.finding_a_id,
                    result.finding_b_id,
                ):
                    corroborations.append(result)
        return corroborations

    def _link_findings(self, finding_a_id: str, finding_b_id: str) -> None:
        """Add each finding id to the other's linked_findings list (no duplicates)."""
        if not finding_a_id or not finding_b_id:
            return
        finding_a = self.graph_manager.get_finding(finding_a_id)
        finding_b = self.graph_manager.get_finding(finding_b_id)
        if finding_a is not None and finding_b_id not in finding_a.linked_findings:
            finding_a.linked_findings.append(finding_b_id)
        if finding_b is not None and finding_a_id not in finding_b.linked_findings:
            finding_b.linked_findings.append(finding_a_id)
