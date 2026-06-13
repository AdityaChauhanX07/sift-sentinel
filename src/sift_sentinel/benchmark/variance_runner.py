"""Multi-run variance harness for SIFT Sentinel benchmarking.

LLM-driven analysis is nondeterministic, so a single benchmark run is noise.
``VarianceRunner`` executes the analysis N times against the same evidence and
ground truth, scores each run, and reports mean ± standard deviation — turning
a single observation into a measurement.
"""

from __future__ import annotations

import datetime
import json
import os
import shutil
import statistics

from .scorer import BenchmarkScore, BenchmarkScorer, GroundTruth
from ..agent.workflow import AnalysisWorkflow


class VarianceRunner:
    """Runs an analysis multiple times against the same evidence and ground truth,
    collecting BenchmarkScores for each run to compute mean ± std.

    This is essential because LLM-driven analysis is nondeterministic.
    A single run is noise. Multiple runs with variance are a measurement.
    """

    def __init__(self, evidence_dir: str, ground_truth: GroundTruth, base_output_dir: str):
        """
        Args:
            evidence_dir: path to evidence files (same for every run)
            ground_truth: the ground truth to score against
            base_output_dir: parent directory for run outputs. Each run gets a subdirectory.
        """
        self._evidence_dir = evidence_dir
        self._ground_truth = ground_truth
        self._base_output_dir = base_output_dir
        self._scores: list[BenchmarkScore] = []
        self._run_metadata: list[dict] = []

    def run(self, n: int = 5, case_id_prefix: str = "bench") -> list[BenchmarkScore]:
        """Execute n analysis runs and score each one.

        Each run:
        1. Creates a fresh output directory: {base_output_dir}/run_{i+1:02d}/
        2. Creates a new AnalysisWorkflow
        3. Initializes evidence (compute manifest, register sources)
        4. Runs validation on all findings
        5. Runs correlation
        6. Syncs metadata and saves state
        7. Scores against ground truth
        8. Records the BenchmarkScore

        NOTE: This runner handles the infrastructure phases (init, validate, correlate).
        The actual triage (Step 2 in the agent workflow — running forensic tools and
        populating findings) is NOT done here because that requires the Claude Code
        agent loop. This runner is designed to be called AFTER the agent has populated
        the evidence graph, or to be extended with a callback for the agent step.

        For benchmarking without the agent loop, you can:
        - Pre-populate findings programmatically (for testing the scoring pipeline)
        - Or run the agent externally and point the runner at existing output dirs

        Returns the list of BenchmarkScores from all runs.
        """
        self._scores = []
        self._run_metadata = []

        os.makedirs(self._base_output_dir, exist_ok=True)

        for i in range(n):
            run_id = f"run_{i + 1:02d}"
            run_output_dir = os.path.join(self._base_output_dir, run_id)
            case_id = f"{case_id_prefix}-{run_id}"

            run_meta = {
                "run_id": run_id,
                "case_id": case_id,
                "output_dir": run_output_dir,
                "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "status": "pending",
                "error": None,
            }

            try:
                # Create fresh workflow
                workflow = AnalysisWorkflow(case_id, self._evidence_dir, run_output_dir)

                # Phase 1: Initialize evidence
                workflow.initialize_evidence()

                # Phase 3: Validate all findings
                workflow.validate_all_findings()

                # Phase 4: Run correlation
                workflow.run_correlation()

                # Save state
                workflow.sync_metadata()
                workflow.save_state()

                # Score
                scorer = BenchmarkScorer(self._ground_truth)
                score = scorer.score(workflow.graph)
                self._scores.append(score)

                run_meta["status"] = "completed"
                run_meta["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

            except Exception as e:
                run_meta["status"] = "failed"
                run_meta["error"] = str(e)
                run_meta["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

            self._run_metadata.append(run_meta)

        return list(self._scores)

    def score_existing_runs(self, run_dirs: list[str]) -> list[BenchmarkScore]:
        """Score pre-existing analysis runs (e.g., from agent-driven analyses).

        Each run_dir should contain an evidence_graph.json from a completed analysis.
        This is the primary way to benchmark agent-driven runs — run the agent N times
        externally, then point this method at the output directories.
        """
        self._scores = []
        scorer = BenchmarkScorer(self._ground_truth)

        for run_dir in run_dirs:
            graph_path = os.path.join(run_dir, "evidence_graph.json")
            if not os.path.isfile(graph_path):
                continue

            try:
                from ..evidence_graph.graph import EvidenceGraphManager
                graph_manager = EvidenceGraphManager.load(graph_path)
                score = scorer.score(graph_manager)
                self._scores.append(score)
            except Exception:
                continue  # skip broken runs

        return list(self._scores)

    def get_scores(self) -> list[BenchmarkScore]:
        """Return all collected scores."""
        return list(self._scores)

    def get_summary_stats(self) -> dict:
        """Compute mean ± std for all key metrics across runs.

        Returns a dict like:
        {
            "n_runs": int,
            "n_successful": int,
            "metrics": {
                "precision": {"mean": float, "std": float},
                ...
            }
        }

        Use statistics.mean and statistics.pstdev (population stdev) for n < 3,
        statistics.stdev (sample stdev) for n >= 3.
        """
        if not self._scores:
            return {"n_runs": 0, "n_successful": 0, "metrics": {}}

        def _compute_stats(values: list[float]) -> dict:
            if not values:
                return {"mean": 0.0, "std": 0.0}
            m = statistics.mean(values)
            if len(values) < 2:
                s = 0.0
            elif len(values) < 3:
                s = statistics.pstdev(values)
            else:
                s = statistics.stdev(values)
            return {"mean": round(m, 4), "std": round(s, 4)}

        metric_names = [
            "precision", "recall", "f1_score", "grounding_rate",
            "residual_hallucination_rate", "factual_hallucinations",
            "total_status_changes", "tool_executions", "duration_seconds",
        ]

        metrics = {}
        for name in metric_names:
            values = [getattr(score, name) for score in self._scores]
            metrics[name] = _compute_stats(values)

        return {
            "n_runs": len(self._run_metadata) if self._run_metadata else len(self._scores),
            "n_successful": len(self._scores),
            "metrics": metrics,
        }

    def save_results(self, filepath: str) -> None:
        """Save all scores and summary stats to a JSON file."""
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        data = {
            "ground_truth": self._ground_truth.to_dict(),
            "run_metadata": self._run_metadata,
            "scores": [s.to_dict() for s in self._scores],
            "summary_stats": self.get_summary_stats(),
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
