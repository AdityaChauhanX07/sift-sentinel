"""SIFT Sentinel command-line entry point.

Wires the analysis workflow and report generator into a runnable CLI. The CLI
provides the infrastructure (evidence mounting, validation, correlation,
reporting); the Claude Code agent runs the actual forensic tool loop.
"""

import argparse
import datetime
import os
import sys

from .agent.workflow import AnalysisWorkflow
from .report.generator import ReportGenerator


def main():
    """SIFT Sentinel CLI — run a forensic analysis from the command line.

    Usage:
        sift-sentinel --evidence /path/to/evidence --output /path/to/output --case-id CASE-001
        sift-sentinel --resume /path/to/previous/output
    """

    parser = argparse.ArgumentParser(
        prog="sift-sentinel",
        description="SIFT Sentinel — A grounded forensic reasoning engine for Protocol SIFT",
        epilog="Built for the Find Evil! Hackathon (https://findevil.devpost.com/)",
    )

    # Mode: new analysis or resume
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--evidence",
        type=str,
        help="Path to directory containing evidence files (disk images, memory captures, logs)",
    )
    mode.add_argument(
        "--resume",
        type=str,
        help="Path to previous output directory to resume an analysis",
    )

    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Output directory for results (default: ./sift-sentinel-output)",
    )
    parser.add_argument(
        "--case-id",
        type=str,
        default=None,
        help="Case identifier (default: auto-generated from timestamp)",
    )
    parser.add_argument(
        "--max-executions",
        type=int,
        default=200,
        help="Maximum tool executions (default: 200)",
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip the validator pipeline (not recommended)",
    )
    parser.add_argument(
        "--skip-correlation",
        action="store_true",
        help="Skip intra-source correlation checks",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Generate report from existing evidence graph without re-running analysis",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )

    args = parser.parse_args()

    # Handle resume mode
    if args.resume:
        return _resume_analysis(args)

    # Handle report-only mode
    if args.report_only and args.output:
        return _report_only(args)

    # New analysis
    return _new_analysis(args)


def _new_analysis(args) -> int:
    """Run a new analysis from scratch."""
    evidence_dir = args.evidence

    if not os.path.isdir(evidence_dir):
        print(f"Error: Evidence directory not found: {evidence_dir}", file=sys.stderr)
        return 1

    # Set defaults
    output_dir = args.output or os.path.join(os.getcwd(), "sift-sentinel-output")
    case_id = args.case_id or f"case-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"

    print(f"SIFT Sentinel v0.1.0")
    print(f"Case ID: {case_id}")
    print(f"Evidence: {evidence_dir}")
    print(f"Output:   {output_dir}")
    print()

    # Initialize workflow
    workflow = AnalysisWorkflow(case_id, evidence_dir, output_dir)
    workflow._max_tool_executions = args.max_executions

    # Phase 1: Initialize evidence
    print("[Phase 1] Initializing evidence and computing integrity manifest...")
    try:
        init_result = workflow.initialize_evidence()
        source_count = len(init_result["sources"])
        file_count = len(init_result["manifest"])
        integrity_ok = init_result["integrity"]["verified"]
        print(f"  → {source_count} evidence source(s) registered, {file_count} file(s) hashed")
        print(f"  → Integrity: {'VERIFIED' if integrity_ok else 'WARNING — integrity check failed'}")
    except Exception as e:
        print(f"  → Error during initialization: {e}", file=sys.stderr)
        print("  → Continuing with available evidence...")
    print()

    # Phase 2: Broad triage
    # NOTE: This is where the Claude Code agent takes over.
    # The CLI provides the infrastructure; the agent runs the actual tools.
    print("[Phase 2] Ready for triage analysis")
    print("  → Use Claude Code or the agent framework to run forensic tools")
    print("  → Available tools: extract_mft_timeline, parse_prefetch, analyze_registry_hive,")
    print("    parse_event_logs, extract_amcache, compute_file_hash, extract_strings")
    print()

    # Phase 3: Validation (if not skipped)
    if not args.skip_validation:
        print("[Phase 3] Running validator pipeline on all findings...")
        try:
            val_result = workflow.validate_all_findings()
            print(f"  → Validated {val_result['total_validated']} finding(s)")
            print(f"  → {val_result['passed']} passed, {val_result['flagged']} flagged, {val_result['eliminated']} eliminated")
        except Exception as e:
            print(f"  → Validation error: {e}", file=sys.stderr)
    else:
        print("[Phase 3] Validation skipped (--skip-validation)")
    print()

    # Phase 4: Correlation (if not skipped)
    if not args.skip_correlation:
        print("[Phase 4] Running intra-source correlation checks...")
        try:
            corr_result = workflow.run_correlation()
            contradictions = corr_result.get("contradictions_found", 0)
            corroborations = corr_result.get("corroborations_found", 0)
            print(f"  → {contradictions} contradiction(s) found, {corroborations} corroboration(s)")
        except Exception as e:
            print(f"  → Correlation error: {e}", file=sys.stderr)
    else:
        print("[Phase 4] Correlation skipped (--skip-correlation)")
    print()

    # Sync and save state
    workflow.sync_metadata()
    saved = workflow.save_state()
    print("[Save] State persisted")
    print(f"  → Graph: {saved['graph']}")
    print(f"  → Execution log: {saved['execution_log']}")
    print()

    # Generate report
    print("[Report] Generating forensic analysis report...")
    reporter = ReportGenerator(workflow.graph)
    report_path = os.path.join(output_dir, "reports", "analysis_report.md")
    reporter.save_report(report_path)
    print(f"  → Report saved: {report_path}")
    print()

    # Print summary
    summary = workflow.get_analysis_summary()
    print("=" * 60)
    print("Analysis Summary")
    print("=" * 60)
    print(f"  Case ID:            {summary['case_id']}")
    print(f"  Evidence sources:   {summary['evidence_sources']}")
    print(f"  Total findings:     {summary['graph_summary']['total_findings']}")
    _print_status_breakdown(summary['graph_summary']['status_breakdown'])
    print(f"  Open contradictions: {summary['open_contradictions']}")
    print(f"  Pending tasks:      {summary['pending_tasks']}")
    print(f"  Tool executions:    {summary['execution_budget']['used']}/{summary['execution_budget']['max']}")
    print()

    return 0


def _resume_analysis(args) -> int:
    """Resume a previous analysis from saved state."""
    output_dir = args.resume

    if not os.path.isdir(output_dir):
        print(f"Error: Output directory not found: {output_dir}", file=sys.stderr)
        return 1

    graph_path = os.path.join(output_dir, "evidence_graph.json")
    if not os.path.isfile(graph_path):
        print(f"Error: No evidence graph found at {graph_path}", file=sys.stderr)
        return 1

    print(f"SIFT Sentinel v0.1.0 — Resuming analysis")
    print(f"Loading from: {output_dir}")
    print()

    try:
        workflow = AnalysisWorkflow.load_existing(output_dir)
        print(f"  → Case ID: {workflow.case_id}")
        print(f"  → Findings loaded: {len(workflow.graph.graph.findings)}")
        print(f"  → Executions restored: {workflow.tracker._counter}")
    except Exception as e:
        print(f"Error loading analysis: {e}", file=sys.stderr)
        return 1

    # Print current state
    summary = workflow.get_analysis_summary()
    print()
    print("Current state:")
    _print_status_breakdown(summary['graph_summary']['status_breakdown'])
    print(f"  Open contradictions: {summary['open_contradictions']}")
    print(f"  Pending tasks:      {summary['pending_tasks']}")
    print()
    print("Analysis resumed. Use Claude Code agent to continue investigation.")

    return 0


def _report_only(args) -> int:
    """Generate a report from an existing evidence graph."""
    output_dir = args.output

    graph_path = os.path.join(output_dir, "evidence_graph.json")
    if not os.path.isfile(graph_path):
        print(f"Error: No evidence graph found at {graph_path}", file=sys.stderr)
        return 1

    print(f"SIFT Sentinel v0.1.0 — Report generation only")

    from .evidence_graph.graph import EvidenceGraphManager
    graph_manager = EvidenceGraphManager.load(graph_path)

    reporter = ReportGenerator(graph_manager)
    report_path = os.path.join(output_dir, "reports", "analysis_report.md")
    reporter.save_report(report_path)
    print(f"Report saved: {report_path}")

    return 0


def _print_status_breakdown(breakdown: dict) -> None:
    """Print finding status breakdown with alignment."""
    for status in ["CONFIRMED", "INFERRED", "HYPOTHESIS", "ELIMINATED"]:
        count = breakdown.get(status, 0)
        if count > 0:
            print(f"    {status:<14} {count}")


if __name__ == "__main__":
    sys.exit(main())
