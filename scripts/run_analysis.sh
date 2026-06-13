#!/bin/bash
# Run SIFT Sentinel Analysis
# Wrapper script for common analysis workflows on the SIFT Workstation
set -e

usage() {
    echo "SIFT Sentinel — Run Analysis"
    echo ""
    echo "Usage:"
    echo "  $0 <evidence_directory> [output_directory] [case_id]"
    echo ""
    echo "Arguments:"
    echo "  evidence_directory   Path to evidence files (required)"
    echo "  output_directory     Where to write results (default: ./sift-sentinel-output)"
    echo "  case_id              Case identifier (default: auto-generated)"
    echo ""
    echo "Examples:"
    echo "  $0 /cases/incident-2026/evidence"
    echo "  $0 /cases/incident-2026/evidence /cases/incident-2026/results CASE-2026-001"
    echo ""
    echo "The script will:"
    echo "  1. Initialize evidence and compute integrity manifest"
    echo "  2. Run the validator pipeline"
    echo "  3. Run intra-source correlation checks"
    echo "  4. Generate the forensic analysis report"
    echo ""
    echo "For agent-driven analysis (with Claude Code), use:"
    echo "  sift-sentinel --evidence <dir> --output <dir>"
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

EVIDENCE_DIR="$1"
OUTPUT_DIR="${2:-./sift-sentinel-output}"
CASE_ID="${3:-}"

if [ ! -d "$EVIDENCE_DIR" ]; then
    echo "Error: Evidence directory not found: $EVIDENCE_DIR"
    exit 1
fi

echo "=================================="
echo "  SIFT Sentinel Analysis"
echo "=================================="
echo ""

# Build the command
CMD="sift-sentinel --evidence \"$EVIDENCE_DIR\" --output \"$OUTPUT_DIR\""
if [ -n "$CASE_ID" ]; then
    CMD="$CMD --case-id \"$CASE_ID\""
fi

# Run it
eval $CMD
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "=================================="
    echo "  Analysis Complete"
    echo "=================================="
    echo ""
    echo "Results saved to: $OUTPUT_DIR"
    echo ""
    echo "Key files:"
    echo "  Report:         $OUTPUT_DIR/reports/analysis_report.md"
    echo "  Evidence graph:  $OUTPUT_DIR/evidence_graph.json"
    echo "  Execution log:   $OUTPUT_DIR/execution_log.json"
    echo "  Manifest:        $OUTPUT_DIR/evidence_manifest.json"
fi

exit $EXIT_CODE
