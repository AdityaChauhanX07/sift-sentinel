"""Benchmark scoring engine for SIFT Sentinel.

Compares an agent's evidence graph against a ground truth specification and
computes precision, recall, grounding, hallucination, and self-correction
metrics. Ground truth and scores round-trip to JSON in the same style as the
evidence graph models.
"""

from __future__ import annotations

import dataclasses
import json
import os
from dataclasses import dataclass, field

from ..evidence_graph.graph import EvidenceGraphManager
from ..evidence_graph.models import Finding, FindingStatus, ValidatorVerdict


@dataclass
class GroundTruthEntry:
    """A single ground truth item — something that should be found in the evidence."""

    entry_id: str
    category: str
    description: str
    artifact_indicators: list[str] = field(default_factory=list)
    required: bool = True

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "category": self.category,
            "description": self.description,
            "artifact_indicators": list(self.artifact_indicators),
            "required": self.required,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "GroundTruthEntry":
        return cls(
            entry_id=data["entry_id"],
            category=data["category"],
            description=data["description"],
            artifact_indicators=list(data.get("artifact_indicators", [])),
            required=data.get("required", True),
        )


@dataclass
class GroundTruth:
    """Complete ground truth for a benchmark case."""

    case_id: str
    case_name: str
    description: str
    source: str
    entries: list[GroundTruthEntry] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "case_name": self.case_name,
            "description": self.description,
            "source": self.source,
            "entries": [e.to_dict() for e in self.entries],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "GroundTruth":
        return cls(
            case_id=data["case_id"],
            case_name=data["case_name"],
            description=data["description"],
            source=data["source"],
            entries=[GroundTruthEntry.from_dict(e) for e in data.get("entries", [])],
        )

    def save(self, filepath: str) -> None:
        """Serialize the ground truth to a JSON file, creating parent dirs as needed."""
        parent = os.path.dirname(filepath)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)

    @classmethod
    def load(cls, filepath: str) -> "GroundTruth":
        """Load a ground truth specification from a JSON file."""
        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return cls.from_dict(data)


@dataclass
class BenchmarkScore:
    """Scoring results from comparing agent output against ground truth."""

    case_id: str
    case_name: str
    ground_truth_source: str

    # Core metrics
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    # Derived metrics
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0

    # Hallucination metrics
    factual_hallucinations: int = 0
    reasoning_hallucinations: int = 0

    # Grounding metrics
    total_findings: int = 0
    grounded_findings: int = 0
    grounding_rate: float = 0.0

    # Self-correction metrics
    total_status_changes: int = 0
    eliminated_findings: int = 0
    residual_hallucination_rate: float = 0.0

    # Validator metrics
    validator_rejections: int = 0
    validator_false_positives: int = 0

    # Timing
    duration_seconds: float = 0.0
    tool_executions: int = 0

    # Match details
    matched_entries: list[dict] = dataclasses.field(default_factory=list)
    unmatched_ground_truth: list[str] = dataclasses.field(default_factory=list)
    unmatched_findings: list[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "case_name": self.case_name,
            "ground_truth_source": self.ground_truth_source,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "f1_score": self.f1_score,
            "factual_hallucinations": self.factual_hallucinations,
            "reasoning_hallucinations": self.reasoning_hallucinations,
            "total_findings": self.total_findings,
            "grounded_findings": self.grounded_findings,
            "grounding_rate": self.grounding_rate,
            "total_status_changes": self.total_status_changes,
            "eliminated_findings": self.eliminated_findings,
            "residual_hallucination_rate": self.residual_hallucination_rate,
            "validator_rejections": self.validator_rejections,
            "validator_false_positives": self.validator_false_positives,
            "duration_seconds": self.duration_seconds,
            "tool_executions": self.tool_executions,
            "matched_entries": [dict(m) for m in self.matched_entries],
            "unmatched_ground_truth": list(self.unmatched_ground_truth),
            "unmatched_findings": list(self.unmatched_findings),
        }


class BenchmarkScorer:
    """Scores an agent's analysis against ground truth.

    Computes precision, recall, grounding rate, hallucination metrics,
    and self-correction statistics.
    """

    def __init__(self, ground_truth: GroundTruth):
        self._ground_truth = ground_truth

    def score(self, graph_manager: EvidenceGraphManager) -> BenchmarkScore:
        """Score the agent's evidence graph against ground truth.

        Matching logic:
        For each ground truth entry, check if any non-ELIMINATED finding matches.
        A finding "matches" if ANY of the entry's artifact_indicators appear in
        the finding's summary (case-insensitive) OR the finding's
        evidence_anchor.artifact_path (case-insensitive).

        A match requires at least one indicator to be found. If an entry has
        multiple indicators, any single match is sufficient (OR logic, not AND).
        """
        graph = graph_manager.graph
        all_findings = graph.findings
        active_findings = [
            f for f in all_findings if f.status != FindingStatus.ELIMINATED
        ]

        score = BenchmarkScore(
            case_id=self._ground_truth.case_id,
            case_name=self._ground_truth.case_name,
            ground_truth_source=self._ground_truth.source,
        )

        # 2. Match each ground truth entry against the active findings.
        matched_finding_ids: set[str] = set()
        for entry in self._ground_truth.entries:
            finding, quality = self._match_finding(entry, active_findings)
            if finding is not None:
                score.true_positives += 1
                matched_finding_ids.add(finding.finding_id)
                score.matched_entries.append(
                    {
                        "ground_truth_id": entry.entry_id,
                        "finding_id": finding.finding_id,
                        "match_quality": quality,
                    }
                )
            else:
                score.false_negatives += 1
                score.unmatched_ground_truth.append(entry.entry_id)

        # 3. Findings not matched to any ground truth entry. These are only
        #    false positives if they have no evidence anchor (fabricated).
        for finding in active_findings:
            if finding.finding_id in matched_finding_ids:
                continue
            score.unmatched_findings.append(finding.finding_id)
            if finding.evidence_anchor is None:
                score.false_positives += 1
                score.factual_hallucinations += 1

        # 4. Derived metrics.
        tp = score.true_positives
        fp = score.false_positives
        fn = score.false_negatives
        score.precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        score.recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        if (score.precision + score.recall) > 0:
            score.f1_score = (
                2 * score.precision * score.recall
                / (score.precision + score.recall)
            )
        else:
            score.f1_score = 0.0

        # 5. Grounding metrics.
        score.total_findings = len(active_findings)
        score.grounded_findings = sum(
            1 for f in active_findings if f.evidence_anchor is not None
        )
        score.grounding_rate = (
            score.grounded_findings / score.total_findings
            if score.total_findings > 0
            else 0.0
        )

        # 6. Self-correction metrics (across ALL findings, including eliminated).
        score.total_status_changes = sum(
            len(f.promotion_history) for f in all_findings
        )
        score.eliminated_findings = sum(
            1 for f in all_findings if f.status == FindingStatus.ELIMINATED
        )

        # 7. Validator metrics.
        score.validator_rejections = sum(
            1
            for f in all_findings
            if any(
                v.verdict in (ValidatorVerdict.FAIL_HARD, ValidatorVerdict.FAIL_SOFT)
                for v in f.validation_results
            )
        )
        # validator_false_positives requires manual review — left at 0.

        # 8. Timing from graph metadata.
        score.duration_seconds = self._compute_duration(
            graph.metadata.analysis_start, graph.metadata.analysis_end
        )
        score.tool_executions = graph.metadata.total_tool_executions

        # 9. Residual hallucination rate — conservative proxy: active findings
        #    with no evidence anchor over total active findings.
        ungrounded = sum(1 for f in active_findings if f.evidence_anchor is None)
        score.residual_hallucination_rate = (
            ungrounded / score.total_findings if score.total_findings > 0 else 0.0
        )

        return score

    def _compute_duration(self, start: str, end: str) -> float:
        """Compute duration in seconds between two ISO 8601 timestamps.

        Returns 0.0 if either timestamp is missing or unparseable.
        """
        if not start or not end:
            return 0.0
        import datetime

        try:
            start_dt = datetime.datetime.fromisoformat(start)
            end_dt = datetime.datetime.fromisoformat(end)
        except ValueError:
            return 0.0
        return (end_dt - start_dt).total_seconds()

    def _match_finding(
        self, entry: GroundTruthEntry, findings: list[Finding]
    ) -> tuple[Finding | None, str]:
        """Find the best matching finding for a ground truth entry.

        Returns (matching_finding, match_quality) or (None, "none").

        If multiple findings match, prefer CONFIRMED > INFERRED > HYPOTHESIS.
        """
        indicators = [ind.lower() for ind in entry.artifact_indicators]
        matches: list[Finding] = []
        for finding in findings:
            summary = finding.summary.lower()
            artifact_path = ""
            if (
                finding.evidence_anchor is not None
                and finding.evidence_anchor.artifact_path is not None
            ):
                artifact_path = finding.evidence_anchor.artifact_path.lower()
            if any(ind in summary or ind in artifact_path for ind in indicators):
                matches.append(finding)

        if not matches:
            return None, "none"

        priority = {
            FindingStatus.CONFIRMED: 0,
            FindingStatus.INFERRED: 1,
            FindingStatus.HYPOTHESIS: 2,
            FindingStatus.ELIMINATED: 3,
        }
        matches.sort(key=lambda f: priority.get(f.status, 99))
        best = matches[0]
        quality = "exact" if best.status == FindingStatus.CONFIRMED else "partial"
        return best, quality

    def format_comparison_table(
        self,
        baseline_scores: list[BenchmarkScore],
        sentinel_scores: list[BenchmarkScore],
    ) -> str:
        """Generate the comparison table as a markdown string.

        Takes lists of scores (from multiple runs) and computes mean ± std for
        each metric. Variance is the credibility element — single-run numbers
        are noise.
        """
        import statistics

        def _stats(values: list[float]) -> tuple[float, float]:
            if not values:
                return 0.0, 0.0
            mean = statistics.fmean(values)
            if len(values) < 3:
                # Population stdev for small samples.
                std = statistics.pstdev(values) if len(values) > 1 else 0.0
            else:
                std = statistics.stdev(values)
            return mean, std

        def _pct_cell(scores: list[BenchmarkScore], attr: str) -> str:
            if not scores:
                return "N/A"
            mean, std = _stats([getattr(s, attr) for s in scores])
            return f"{mean * 100:.1f}% ± {std * 100:.1f}%"

        def _num_cell(scores: list[BenchmarkScore], attr: str) -> str:
            if not scores:
                return "N/A"
            mean, std = _stats([float(getattr(s, attr)) for s in scores])
            return f"{mean:.1f} ± {std:.1f}"

        n_base = len(baseline_scores)
        n_sent = len(sentinel_scores)

        # Self-corrections are not meaningful for the baseline (it has no
        # status lifecycle), so that cell is N/A.
        rows = [
            ("Precision", _pct_cell(baseline_scores, "precision"),
             _pct_cell(sentinel_scores, "precision")),
            ("Recall", _pct_cell(baseline_scores, "recall"),
             _pct_cell(sentinel_scores, "recall")),
            ("Grounding Rate", _pct_cell(baseline_scores, "grounding_rate"),
             _pct_cell(sentinel_scores, "grounding_rate")),
            ("Residual Hallucination Rate",
             _pct_cell(baseline_scores, "residual_hallucination_rate"),
             _pct_cell(sentinel_scores, "residual_hallucination_rate")),
            ("Factual Hallucinations",
             _num_cell(baseline_scores, "factual_hallucinations"),
             _num_cell(sentinel_scores, "factual_hallucinations")),
            ("Reasoning Hallucinations",
             _num_cell(baseline_scores, "reasoning_hallucinations"),
             _num_cell(sentinel_scores, "reasoning_hallucinations")),
            ("Self-Corrections", "N/A",
             _num_cell(sentinel_scores, "total_status_changes")),
            ("Tool Executions", _num_cell(baseline_scores, "tool_executions"),
             _num_cell(sentinel_scores, "tool_executions")),
            ("Duration (seconds)", _num_cell(baseline_scores, "duration_seconds"),
             _num_cell(sentinel_scores, "duration_seconds")),
        ]

        label_w = 30
        col_w = 25
        lines: list[str] = []
        # Header.
        lines.append(
            f"{'':<{label_w}}{'Protocol SIFT Baseline':<{col_w}}{'SIFT Sentinel'}"
        )
        lines.append(
            f"{'':<{label_w}}"
            f"{f'(mean ± std, n={n_base})':<{col_w}}"
            f"{f'(mean ± std, n={n_sent})'}"
        )
        lines.append(
            "─" * label_w + "┬" + "─" * (col_w - 1) + "┬" + "─" * (col_w - 1)
        )
        for label, base_cell, sent_cell in rows:
            lines.append(
                f"{label:<{label_w}}│ {base_cell:<{col_w - 2}}│ {sent_cell}"
            )
        return "\n".join(lines)
