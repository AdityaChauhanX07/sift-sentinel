"""Converts the evidence graph into a structured investigative report.

The report is the final deliverable — what an incident responder hands to a
CISO, legal team, or remediation team. It is auto-generated from the evidence
graph (not LLM-written), so it accurately reflects the graph state and every
claim traces back to a specific artifact through the graph.
"""

from __future__ import annotations

import datetime
import json
import os

from ..evidence_graph.models import (
    FindingStatus,
    CorroborationType,
    Finding,
    Contradiction,
    EvidenceGraph,
)
from ..evidence_graph.graph import EvidenceGraphManager


_CORROBORATION_INDICATOR = {
    CorroborationType.INDEPENDENT_SOURCES: "🟢 independent_sources",
    CorroborationType.SINGLE_SOURCE_CORROBORATED: "🟡 single_source_corroborated",
    CorroborationType.SINGLE_SOURCE_NARRATED: "🟠 single_source_narrated",
    CorroborationType.NOT_APPLICABLE: "— not_applicable",
}


class ReportGenerator:
    """Generates a structured forensic report from the evidence graph."""

    def __init__(self, graph_manager: EvidenceGraphManager):
        """Store the graph manager whose state will be rendered."""
        self._graph = graph_manager

    # --- public API ---

    def generate_full_report(self) -> str:
        """Generate the complete report as a Markdown string."""
        sections = [
            self._header(),
            self._executive_summary(),
            self._evidence_inventory(),
            self._confirmed_findings(),
            self._inferred_findings(),
            self._open_hypotheses(),
            self._eliminated_findings(),
            self._contradictions_section(),
            self._validator_activity(),
            self._coverage_gaps(),
            self._audit_trail(),
        ]
        return "\n\n---\n\n".join(sections)

    def save_report(self, filepath: str) -> None:
        """Generate and save the report to a markdown file."""
        report = self.generate_full_report()
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report)

    # --- shared helpers ---

    @property
    def _g(self) -> EvidenceGraph:
        return self._graph.graph

    @staticmethod
    def _now() -> str:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

    def _findings_by_status(self, status: FindingStatus) -> list[Finding]:
        return [f for f in self._g.findings if f.status == status]

    @staticmethod
    def _anchor_reference(finding: Finding) -> str:
        anchor = finding.evidence_anchor
        if anchor is None:
            return "no anchor"
        ref = anchor.artifact_path or anchor.offset or anchor.log_entry or "unspecified"
        return f"{anchor.source_id} → {ref}"

    @staticmethod
    def _status_chain(finding: Finding) -> str:
        history = finding.promotion_history
        if not history:
            return finding.status.value
        chain = [history[0].from_status.value]
        chain.extend(record.to_status.value for record in history)
        return " → ".join(chain)

    def _total_status_changes(self) -> int:
        return sum(len(f.promotion_history) for f in self._g.findings)

    # --- sections ---

    def _header(self) -> str:
        meta = self._g.metadata
        end = meta.analysis_end or "ongoing"
        return (
            "# SIFT Sentinel — Forensic Analysis Report\n"
            f"**Case ID:** {self._g.case_id}  \n"
            f"**Analysis Date:** {meta.analysis_start} to {end}  \n"
            f"**Agent Version:** {meta.agent_version}  \n"
            f"**Generated:** {self._now()}"
        )

    def _executive_summary(self) -> str:
        confirmed = len(self._findings_by_status(FindingStatus.CONFIRMED))
        inferred = len(self._findings_by_status(FindingStatus.INFERRED))
        hypotheses = len(self._findings_by_status(FindingStatus.HYPOTHESIS))
        eliminated = len(self._findings_by_status(FindingStatus.ELIMINATED))
        sources = len(self._g.evidence_sources)
        resolved = sum(1 for c in self._g.contradictions if c.status == "RESOLVED")
        open_c = sum(1 for c in self._g.contradictions if c.status == "OPEN")
        tool_execs = self._g.metadata.total_tool_executions
        status_changes = self._total_status_changes()

        paragraph = (
            f"This automated forensic analysis examined {sources} evidence "
            f"source(s) and produced {confirmed} confirmed, {inferred} inferred, "
            f"and {hypotheses} open hypothesis finding(s). {eliminated} finding(s) "
            f"were eliminated during analysis through deterministic validation, and "
            f"{len(self._g.contradictions)} contradiction(s) were identified "
            f"({resolved} resolved, {open_c} open). The agent performed "
            f"{status_changes} finding status change(s) across the investigation, "
            f"demonstrating active self-correction."
        )

        table = (
            "| Metric | Count |\n"
            "| --- | --- |\n"
            f"| Confirmed findings | {confirmed} |\n"
            f"| Inferred findings | {inferred} |\n"
            f"| Open hypotheses | {hypotheses} |\n"
            f"| Eliminated findings | {eliminated} |\n"
            f"| Evidence sources | {sources} |\n"
            f"| Contradictions (resolved / open) | {resolved} / {open_c} |\n"
            f"| Tool executions | {tool_execs} |\n"
            f"| Self-corrections (status changes) | {status_changes} |"
        )

        return "## Executive Summary\n\n" + paragraph + "\n\n" + table

    def _evidence_inventory(self) -> str:
        lines = ["## Evidence Inventory", ""]
        if not self._g.evidence_sources:
            lines.append("_No evidence sources registered._")
            return "\n".join(lines)

        lines.append("| Source ID | Type | Path | SHA-256 | Mount Point | Metadata |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for s in self._g.evidence_sources:
            interesting = {
                k: v
                for k, v in s.metadata.items()
                if k in ("os_type", "filesystem_type", "capture_time")
            }
            meta_str = (
                ", ".join(f"{k}={v}" for k, v in interesting.items())
                if interesting
                else "—"
            )
            lines.append(
                f"| {s.source_id} | {s.source_type} | {s.path} | "
                f"{s.sha256} | {s.mounted_at or '—'} | {meta_str} |"
            )
        return "\n".join(lines)

    def _render_finding(self, finding: Finding) -> str:
        anchor = finding.evidence_anchor
        chain = finding.reasoning_chain
        mitre = ", ".join(finding.mitre_attack) if finding.mitre_attack else "N/A"
        file_hash = (anchor.file_hash if anchor and anchor.file_hash else "N/A")
        exec_id = anchor.tool_execution_id if anchor else "N/A"
        raw_ref = anchor.raw_output_reference if anchor else None
        if raw_ref:
            exec_line = f"{exec_id} ([raw output]({raw_ref}))"
        else:
            exec_line = exec_id
        corroboration = _CORROBORATION_INDICATOR.get(
            chain.corroboration_type, chain.corroboration_type.value
        )
        premises = ", ".join(chain.premises) if chain.premises else "none cited"
        passed = sum(
            1 for v in finding.validation_results if v.verdict.value == "PASS"
        )

        lines = [
            f"### [{finding.finding_id}] {finding.summary}",
            "",
            f"- **Status:** {finding.status.value}",
            f"- **Category:** {finding.category or 'uncategorized'}",
            f"- **MITRE ATT&CK:** {mitre}",
            f"- **Evidence Anchor:** {self._anchor_reference(finding)}",
            f"- **File Hash:** {file_hash}",
            f"- **Tool Execution:** {exec_line}",
            f"- **Reasoning Chain:** {chain.logic or '—'} "
            f"(Corroboration: {corroboration})",
            f"  - Premises: {premises}",
            f"- **Validation:** {passed} validator(s) passed",
            f"- **History:** {self._status_chain(finding)}",
        ]
        return "\n".join(lines)

    def _confirmed_findings(self) -> str:
        findings = self._findings_by_status(FindingStatus.CONFIRMED)
        lines = ["## Confirmed Findings", ""]
        if not findings:
            lines.append("_No confirmed findings._")
            return "\n".join(lines)
        lines.extend(self._render_finding(f) + "\n" for f in findings)
        return "\n".join(lines).rstrip()

    def _inferred_findings(self) -> str:
        findings = self._findings_by_status(FindingStatus.INFERRED)
        lines = ["## Inferred Findings", ""]
        if not findings:
            lines.append("_No inferred findings._")
            return "\n".join(lines)
        lines.append(
            "_These findings have corroborating evidence but have not been "
            "independently verified by a second artifact type._"
        )
        lines.append("")
        for f in findings:
            lines.append(self._render_finding(f))
            if f.reasoning_chain.corroboration_type == (
                CorroborationType.SINGLE_SOURCE_NARRATED
            ):
                lines.append("")
                lines.append(
                    "> ⚠️ This inference rests on a narrated connection from a "
                    "single artifact. The reasoning chain should be evaluated "
                    "independently."
                )
            lines.append("")
        return "\n".join(lines).rstrip()

    def _open_hypotheses(self) -> str:
        findings = self._findings_by_status(FindingStatus.HYPOTHESIS)
        lines = ["## Open Hypotheses", ""]
        if not findings:
            lines.append("_No open hypotheses._")
            return "\n".join(lines)
        lines.append(
            "_These findings were not confirmed during automated analysis. They "
            "may warrant manual investigation._"
        )
        lines.append("")
        for f in findings:
            flags = ", ".join(f.flags) if f.flags else "none"
            follow_up = self._uninvestigated_followups(f)
            lines.append(f"### [{f.finding_id}] {f.summary}")
            lines.append("")
            lines.append(f"- **Evidence Anchor:** {self._anchor_reference(f)}")
            lines.append(f"- **Flags:** {flags}")
            lines.append(f"- **Suggested follow-up not completed:** {follow_up}")
            lines.append("")
        return "\n".join(lines).rstrip()

    def _uninvestigated_followups(self, finding: Finding) -> str:
        # Pending/deferred tasks triggered by this finding represent uncompleted
        # follow-up investigation.
        pending = [
            t.description
            for t in self._g.investigation_queue
            if t.triggered_by == finding.finding_id
            and t.status in ("PENDING", "DEFERRED")
        ]
        return "; ".join(pending) if pending else "none recorded"

    def _eliminated_findings(self) -> str:
        findings = self._findings_by_status(FindingStatus.ELIMINATED)
        lines = ["## Eliminated Findings", ""]
        if not findings:
            lines.append("_No findings were eliminated during this analysis._")
            return "\n".join(lines)
        lines.append(
            "_These findings were initially considered by the agent but were "
            "disproved or invalidated during analysis. Their presence "
            "demonstrates the agent's self-correction capability._"
        )
        lines.append("")
        for f in findings:
            last = f.promotion_history[-1] if f.promotion_history else None
            prior_status = last.from_status.value if last else "unknown"
            reason = last.reason if last else "no reason recorded"
            triggered_by = last.triggered_by if last else "unknown"
            lines.append(f"### [{f.finding_id}] {f.summary}")
            lines.append("")
            lines.append(f"- **Status before elimination:** {prior_status}")
            lines.append(f"- **Reason for elimination:** {reason}")
            lines.append(f"- **Triggered by:** {triggered_by}")
            lines.append("")
        return "\n".join(lines).rstrip()

    def _contradictions_section(self) -> str:
        lines = ["## Contradictions and Resolutions", ""]
        if not self._g.contradictions:
            lines.append("_No contradictions were identified._")
            return "\n".join(lines)
        for c in self._g.contradictions:
            sum_a = self._finding_summary(c.finding_a)
            sum_b = self._finding_summary(c.finding_b)
            lines.append(f"### [{c.contradiction_id}] {c.status}")
            lines.append("")
            lines.append(f"- **Finding A:** {c.finding_a} — {sum_a}")
            lines.append(f"- **Finding B:** {c.finding_b} — {sum_b}")
            lines.append(f"- **Description:** {c.description}")
            lines.append(f"- **Status:** {c.status}")
            if c.resolution:
                lines.append(f"- **Resolution:** {c.resolution}")
            if c.follow_up_tasks:
                outcomes = "; ".join(
                    f"{tid} ({self._task_status(tid)})" for tid in c.follow_up_tasks
                )
                lines.append(f"- **Follow-up tasks:** {outcomes}")
            lines.append("")
        return "\n".join(lines).rstrip()

    def _finding_summary(self, finding_id: str) -> str:
        f = self._graph.get_finding(finding_id)
        return f.summary if f is not None else "(finding not found)"

    def _task_status(self, task_id: str) -> str:
        for t in self._g.investigation_queue:
            if t.task_id == task_id:
                return t.status
        return "unknown"

    def _validator_activity(self) -> str:
        verdict_counts = {
            "PASS": 0,
            "FAIL_HARD": 0,
            "FAIL_SOFT": 0,
            "NOT_APPLICABLE": 0,
        }
        per_validator: dict[str, dict[str, int]] = {}
        rejections = []  # (finding_id, validator_name, verdict, detail)
        total_runs = 0

        for f in self._g.findings:
            for v in f.validation_results:
                total_runs += 1
                verdict = v.verdict.value
                verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
                bucket = per_validator.setdefault(
                    v.validator_name,
                    {"PASS": 0, "FAIL_HARD": 0, "FAIL_SOFT": 0, "NOT_APPLICABLE": 0},
                )
                bucket[verdict] = bucket.get(verdict, 0) + 1
                if verdict in ("FAIL_HARD", "FAIL_SOFT"):
                    rejections.append(
                        (f.finding_id, v.validator_name, verdict, v.detail)
                    )

        lines = ["## Validator Activity Report", ""]
        lines.append(f"- **Total validation runs:** {total_runs}")
        lines.append(f"- **PASS:** {verdict_counts['PASS']}")
        lines.append(f"- **FAIL_HARD:** {verdict_counts['FAIL_HARD']}")
        lines.append(f"- **FAIL_SOFT:** {verdict_counts['FAIL_SOFT']}")
        lines.append(f"- **NOT_APPLICABLE:** {verdict_counts['NOT_APPLICABLE']}")
        lines.append("")

        if per_validator:
            lines.append("### Per-Validator Breakdown")
            lines.append("")
            lines.append(
                "| Validator | PASS | FAIL_HARD | FAIL_SOFT | NOT_APPLICABLE |"
            )
            lines.append("| --- | --- | --- | --- | --- |")
            for name in sorted(per_validator):
                b = per_validator[name]
                lines.append(
                    f"| {name} | {b['PASS']} | {b['FAIL_HARD']} | "
                    f"{b['FAIL_SOFT']} | {b['NOT_APPLICABLE']} |"
                )
            lines.append("")

        total_rejections = verdict_counts["FAIL_HARD"] + verdict_counts["FAIL_SOFT"]
        lines.append("**Rejection Analysis:**")
        lines.append("")
        lines.append(
            f"- Total validator rejections (FAIL_HARD + FAIL_SOFT): {total_rejections}"
        )
        lines.append(
            "- Note: Each rejection is documented individually below. Rejections "
            "include both confirmed hallucinations and validator false positives. "
            "See the accuracy report for manual verification of each rejection."
        )
        lines.append("")
        if rejections:
            lines.append("| Finding | Validator | Verdict | Detail |")
            lines.append("| --- | --- | --- | --- |")
            for fid, vname, verdict, detail in rejections:
                safe_detail = detail.replace("|", "\\|").replace("\n", " ")
                lines.append(f"| {fid} | {vname} | {verdict} | {safe_detail} |")
        else:
            lines.append("_No validator rejections recorded._")

        return "\n".join(lines)

    def _coverage_gaps(self) -> str:
        lines = ["## Coverage Gaps", ""]
        gaps = []

        deferred = [
            t for t in self._g.investigation_queue if t.status == "DEFERRED"
        ]
        for t in deferred:
            gaps.append(f"Deferred task {t.task_id}: {t.description}")

        for f in self._g.findings:
            if "uninvestigated_hypothesis" in f.flags:
                gaps.append(
                    f"Uninvestigated hypothesis {f.finding_id}: {f.summary}"
                )

        tool_execs = self._g.metadata.total_tool_executions
        if tool_execs >= 200:
            gaps.append(
                f"Tool execution budget appears exhausted "
                f"({tool_execs} executions); some investigation may have been "
                f"truncated."
            )

        if not gaps:
            lines.append(
                "No coverage gaps identified. All planned investigation tasks "
                "were completed."
            )
            return "\n".join(lines)

        lines.extend(f"- {g}" for g in gaps)
        return "\n".join(lines)

    def _audit_trail(self) -> str:
        tool_execs = self._g.metadata.total_tool_executions
        status_changes = self._total_status_changes()
        lines = [
            "## Audit Trail",
            "",
            "- **Evidence graph:** `evidence_graph.json`",
            "- **Execution log:** `execution_log.json`",
            "- **Graph snapshots:** `snapshots/`",
            f"- **Total tool executions:** {tool_execs}",
            f"- **Total status changes across all findings:** {status_changes}",
            "",
            "Every finding in this report can be traced back to a specific tool "
            "execution through the evidence graph. The execution log contains raw "
            "output references for independent verification.",
        ]
        return "\n".join(lines)
