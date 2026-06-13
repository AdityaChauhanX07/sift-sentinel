"""Workflow orchestrator that ties all SIFT Sentinel components together.

``AnalysisWorkflow`` is the infrastructure layer for a full analysis. It
coordinates evidence mounting, typed MCP tool execution, the evidence graph,
the validator pipeline, and the correlation engine. It does NOT run the LLM
agent loop — Claude Code does that — it provides the methods the agent calls
into.
"""

from __future__ import annotations

import datetime
import importlib.resources
import json
import os

from ..evidence_graph.models import (
    FindingStatus,
    CorroborationType,
    EvidenceAnchor,
    EvidenceSource,
    ValidationResult,
    ValidatorVerdict,
)
from ..evidence_graph.graph import EvidenceGraphManager
from ..validators import create_default_pipeline, ValidatorPipeline
from ..correlation.engine import CorrelationEngine
from ..mcp_server.response_envelope import ExecutionTracker, ToolResponse
from ..mcp_server.evidence_mount import EvidenceMount


def load_prompt(name: str) -> str:
    """Load a prompt markdown file from the agent package.

    Args:
        name: prompt filename without extension, e.g. "system_prompt" or
            "self_review_prompt".

    Returns the content as a string. Falls back to reading from the filesystem
    relative to this file if importlib.resources fails.
    """
    try:
        pkg = importlib.resources.files("sift_sentinel.agent")
        return (pkg / f"{name}.md").read_text(encoding="utf-8")
    except Exception:
        prompt_path = os.path.join(os.path.dirname(__file__), f"{name}.md")
        with open(prompt_path, "r", encoding="utf-8") as f:
            return f.read()


class AnalysisWorkflow:
    """Orchestrates a full SIFT Sentinel forensic analysis.

    Coordinates evidence mounting and integrity verification, tool execution
    via typed MCP wrappers, evidence graph population and lifecycle management,
    validator pipeline execution (post-entry, visible), intra-source
    correlation, and report generation.

    It does NOT run the LLM agent loop itself — that's Claude Code's job. This
    class provides the infrastructure the agent calls into.
    """

    def __init__(self, case_id: str, evidence_dir: str, output_dir: str):
        """Initialize a new analysis workflow.

        Args:
            case_id: unique identifier for this case.
            evidence_dir: path to the directory containing evidence files.
            output_dir: path where all outputs will be written (logs, reports,
                snapshots).
        """
        self.case_id = case_id
        self.evidence_dir = evidence_dir
        self.output_dir = output_dir

        # Create output subdirectories
        self.raw_output_dir = os.path.join(output_dir, "raw")
        self.snapshot_dir = os.path.join(output_dir, "snapshots")
        self.report_dir = os.path.join(output_dir, "reports")
        for d in [self.raw_output_dir, self.snapshot_dir, self.report_dir]:
            os.makedirs(d, exist_ok=True)

        # Initialize components
        self.graph = EvidenceGraphManager(case_id)
        self.tracker = ExecutionTracker()
        self.pipeline = create_default_pipeline()
        self.evidence_mount = EvidenceMount(
            evidence_dir, os.path.join(output_dir, "mnt")
        )
        self.correlation_engine = CorrelationEngine(self.graph)

        # Load prompts
        self.system_prompt = load_prompt("system_prompt")
        self.self_review_prompt = load_prompt("self_review_prompt")

        # Analysis state
        self._tool_execution_count = 0
        self._max_tool_executions = 200
        self._investigation_iterations = 0
        self._max_investigation_iterations = 10

    def initialize_evidence(self) -> dict:
        """Phase 1: Mount evidence and compute the integrity manifest.

        Returns a summary dict with the manifest, the mounted source info, and
        the integrity verification result.
        """
        # Compute manifest
        manifest = self.evidence_mount.compute_manifest()

        # Save manifest
        self.evidence_mount.save_manifest(
            os.path.join(self.output_dir, "evidence_manifest.json")
        )

        # Register evidence sources in the graph by walking the evidence dir
        sources_info = []
        for filename in os.listdir(self.evidence_dir):
            filepath = os.path.join(self.evidence_dir, filename)
            if not os.path.isfile(filepath):
                continue

            # Detect source type from extension
            ext = os.path.splitext(filename)[1].lower()
            source_type = "unknown"
            if ext in (".e01", ".raw", ".dd", ".img", ".iso", ".vmdk"):
                source_type = "disk_image"
            elif ext in (".mem", ".dmp", ".lime", ".raw"):
                # .raw could be disk or memory — check size/context
                source_type = "memory_capture"
            elif ext in (".evtx", ".log", ".csv", ".json"):
                source_type = "log_file"
            elif ext in (".pcap", ".pcapng"):
                source_type = "network_capture"

            # Get hash from manifest
            file_hash = manifest.get(filepath, "unknown")

            # Mount it
            mount_name = os.path.splitext(filename)[0]
            mount_result = self.evidence_mount.mount_image(
                filepath, mount_name, f"pending-{mount_name}"
            )

            # Register in graph
            source = self.graph.add_source(
                source_type=source_type,
                path=filepath,
                sha256=file_hash,
                mounted_at=mount_result.get("mount_point", ""),
                metadata={
                    "filename": filename,
                    "mount_method": mount_result.get("method"),
                    "mount_success": mount_result.get("success", False),
                },
            )

            # Track with the real source_id
            sources_info.append(
                {
                    "source_id": source.source_id,
                    "filename": filename,
                    "source_type": source_type,
                    "mount_point": mount_result.get("mount_point", ""),
                    "mount_success": mount_result.get("success", False),
                }
            )

        # Verify integrity
        integrity = self.evidence_mount.verify_integrity()

        # Save initial graph snapshot
        self.graph.save_snapshot(self.snapshot_dir, "00_initialized")

        return {
            "manifest": manifest,
            "sources": sources_info,
            "integrity": integrity,
        }

    def validate_finding(self, finding_id: str) -> dict:
        """Run the validator pipeline against a finding and apply the results.

        Post-entry visible validation: run all validators, attach results,
        eliminate on a HARD failure, flag on a SOFT failure, and return a
        summary with the action taken.
        """
        finding = self.graph.get_finding(finding_id)
        if finding is None:
            return {"error": f"Finding {finding_id} not found"}

        # Build validator context from current state
        context = self._build_validator_context()

        # Run pipeline
        results = self.pipeline.validate_finding(finding, context)

        # Attach results to finding
        for result in results:
            self.graph.add_validation_result(finding_id, result)

        # Process results
        summary = self.pipeline.summarize(results)

        hard_failures = self.pipeline.get_hard_failures(results)
        soft_failures = self.pipeline.get_soft_failures(results)

        if hard_failures:
            # Eliminate the finding — this is the visible self-correction
            reasons = "; ".join(
                f"{r.validator_name}: {r.detail}" for r in hard_failures
            )
            self.graph.eliminate_finding(
                finding_id,
                reason=f"Eliminated by deterministic validators: {reasons}",
                triggered_by=f"validator:{hard_failures[0].validator_name}",
            )
            summary["action_taken"] = "ELIMINATED"
        elif soft_failures:
            # Add flags but don't eliminate
            for r in soft_failures:
                flag_name = f"{r.validator_name}_flag"
                self.graph.add_flag(finding_id, flag_name)
            summary["action_taken"] = "FLAGGED"
        else:
            summary["action_taken"] = "PASSED"

        return summary

    def validate_all_findings(self) -> dict:
        """Run validation on all non-eliminated findings. Returns a summary."""
        results = {}
        for finding in self.graph.graph.findings:
            if finding.status != FindingStatus.ELIMINATED:
                results[finding.finding_id] = self.validate_finding(
                    finding.finding_id
                )

        # Save snapshot after validation
        self.graph.save_snapshot(self.snapshot_dir, "01_validated")

        return {
            "total_validated": len(results),
            "eliminated": sum(
                1 for r in results.values() if r.get("action_taken") == "ELIMINATED"
            ),
            "flagged": sum(
                1 for r in results.values() if r.get("action_taken") == "FLAGGED"
            ),
            "passed": sum(
                1 for r in results.values() if r.get("action_taken") == "PASSED"
            ),
            "details": results,
        }

    def run_correlation(self) -> dict:
        """Run intra-source (and cross-source if available) correlation checks."""
        result = self.correlation_engine.run_all_checks()

        # Save snapshot after correlation
        self.graph.save_snapshot(self.snapshot_dir, "02_correlated")

        return result

    def check_execution_budget(self) -> dict:
        """Check remaining tool execution budget.

        Returns: {"used": int, "remaining": int, "max": int, "warning": bool}.
        """
        used = self.tracker._counter
        remaining = self._max_tool_executions - used
        return {
            "used": used,
            "remaining": remaining,
            "max": self._max_tool_executions,
            "warning": remaining <= 40,  # warn at 80% usage
        }

    def _build_validator_context(self) -> dict:
        """Build the context dict that validators need."""
        # Evidence sources as list of dicts
        evidence_sources = [s.to_dict() for s in self.graph.graph.evidence_sources]

        # Raw output paths from execution tracker
        raw_output_paths = self.tracker.get_raw_outputs_map()

        # Raw outputs — read small files directly, reference paths for large ones
        raw_outputs = {}
        for exec_id, path in raw_output_paths.items():
            try:
                file_size = os.path.getsize(path) if os.path.exists(path) else 0
                if file_size < 1_000_000:  # <1MB: read into memory
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        raw_outputs[exec_id] = f.read()
            except (OSError, IOError):
                pass

        # Build normalized outputs from parsed tool responses
        normalized_outputs = {}
        for response in self.tracker.get_log():
            if response.parsed_output:
                try:
                    normalized_outputs[response.execution_id] = json.dumps(
                        response.parsed_output, default=str
                    )
                except (TypeError, ValueError):
                    pass

        return {
            "evidence_sources": evidence_sources,
            "raw_outputs": raw_outputs,
            "raw_output_paths": raw_output_paths,
            "normalized_outputs": normalized_outputs,
        }

    def sync_metadata(self) -> None:
        """Sync runtime counters into the evidence graph metadata.

        Call this before generating reports or saving state to ensure
        metadata reflects actual execution counts.
        """
        self.graph.graph.metadata.total_tool_executions = self.tracker._counter
        if not self.graph.graph.metadata.analysis_end:
            self.graph.graph.metadata.analysis_end = datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()

    def save_state(self) -> dict:
        """Save all current state to disk. Returns paths of saved files."""
        self.sync_metadata()
        graph_path = os.path.join(self.output_dir, "evidence_graph.json")
        log_path = os.path.join(self.output_dir, "execution_log.json")

        self.graph.save(graph_path)
        self.tracker.save_log(log_path)

        return {
            "graph": graph_path,
            "execution_log": log_path,
        }

    def get_analysis_summary(self) -> dict:
        """Get a summary of the current analysis state for the agent."""
        budget = self.check_execution_budget()
        graph_summary = self.graph.get_summary()

        return {
            "case_id": self.case_id,
            "execution_budget": budget,
            "graph_summary": graph_summary,
            "evidence_sources": len(self.graph.graph.evidence_sources),
            "open_contradictions": len(
                [c for c in self.graph.graph.contradictions if c.status == "OPEN"]
            ),
            "pending_tasks": len(self.graph.get_pending_tasks()),
        }

    @classmethod
    def load_existing(cls, output_dir: str) -> "AnalysisWorkflow":
        """Load a previously saved analysis to continue it.

        Reads the evidence graph and execution log from the output directory.
        """
        graph_path = os.path.join(output_dir, "evidence_graph.json")
        log_path = os.path.join(output_dir, "execution_log.json")

        # Load the graph to get case_id and evidence_dir
        graph_manager = EvidenceGraphManager.load(graph_path)

        # Derive evidence_dir from the first source's path, if any
        evidence_dir = ""
        if graph_manager.graph.evidence_sources:
            first_source_path = graph_manager.graph.evidence_sources[0].path
            evidence_dir = os.path.dirname(first_source_path)

        workflow = cls(
            case_id=graph_manager.graph.case_id,
            evidence_dir=evidence_dir,
            output_dir=output_dir,
        )
        workflow.graph = graph_manager
        # Rewire the correlation engine to the loaded graph (the constructor
        # bound it to a fresh, empty one).
        workflow.correlation_engine = CorrelationEngine(graph_manager)

        # Reload execution log if it exists
        if os.path.exists(log_path):
            with open(log_path, "r") as f:
                log_data = json.load(f)
            for entry in log_data:
                response = ToolResponse.from_dict(entry)
                workflow.tracker.record(response)
            workflow.tracker._counter = len(log_data)

        return workflow
