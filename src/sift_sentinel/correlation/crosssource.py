"""Cross-Source Correlation Checks

Correlates findings across different evidence source types (disk + memory,
disk + network logs, etc.) to detect contradictions and validate findings.

STATUS: Architecture-ready. These checks activate when multiple evidence
source types are available (determined by Phase 0 evidence data assessment).
If only a single source type is available, the intra-source correlation in
checks.py provides equivalent cross-validation within that source.

See the project plan's Phase 4.2 for full design.
"""

from dataclasses import dataclass, field
from ..evidence_graph.models import Finding, FindingStatus
from .checks import CorrelationResult, _extract_filename, _is_active


def check_process_existence(findings: list[Finding]) -> list[CorrelationResult]:
    """Cross-check: Process in memory vs executable on disk.

    - Present in memory, absent on disk → possible fileless malware or deleted executable
    - Present on disk, absent in memory → not running at capture time

    Requires findings from both disk analysis (file_artifact) and memory analysis (process_activity).
    """
    results = []
    active = [f for f in findings if _is_active(f)]

    # Identify memory process findings
    memory_processes = [f for f in active if "process" in f.summary.lower() or f.category == "process_activity"]

    # Identify disk file findings
    disk_files = [f for f in active if f.category == "file_artifact"]

    if not memory_processes or not disk_files:
        return results  # Need both source types

    for proc_finding in memory_processes:
        proc_name = _extract_filename(proc_finding)
        if not proc_name:
            continue

        # Check if corresponding file exists on disk
        matching_file = None
        for file_finding in disk_files:
            file_name = _extract_filename(file_finding)
            if file_name and file_name.lower() == proc_name.lower():
                matching_file = file_finding
                break

        if matching_file is None:
            results.append(CorrelationResult(
                check_name="process_existence",
                finding_a_id=proc_finding.finding_id,
                finding_b_id="N/A",
                is_contradiction=True,
                severity="HIGH",
                description=f"Process '{proc_name}' found in memory ({proc_finding.finding_id}) but no corresponding executable found on disk. Possible fileless malware or deleted executable.",
                follow_up_suggestions=[
                    "Check MFT for deletion record of the executable",
                    "Search USN journal for file creation/deletion events",
                    "Check for process hollowing or injection indicators",
                ],
            ))
        else:
            results.append(CorrelationResult(
                check_name="process_existence",
                finding_a_id=proc_finding.finding_id,
                finding_b_id=matching_file.finding_id,
                is_contradiction=False,
                severity="LOW",
                description=f"Process '{proc_name}' in memory ({proc_finding.finding_id}) corroborated by executable on disk ({matching_file.finding_id}).",
            ))

    return results


def check_network_activity(findings: list[Finding]) -> list[CorrelationResult]:
    """Cross-check: Network connections in memory vs log entries.

    - Connection in memory, absent from logs → possible log tampering
    - Connection in logs, no matching process in memory → process terminated before capture

    Requires findings from memory analysis and log analysis.
    """
    results = []
    active = [f for f in findings if _is_active(f)]

    # Identify network findings from memory
    memory_network = [f for f in active if f.category == "network_activity" and "memory" in f.summary.lower()]

    # Identify network findings from logs
    log_network = [f for f in active if f.category == "network_activity" and ("log" in f.summary.lower() or "event" in f.summary.lower())]

    if not memory_network or not log_network:
        return results

    # Basic cross-reference by IP address
    import re
    ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

    for mem_finding in memory_network:
        mem_ips = set(ip_pattern.findall(mem_finding.summary))

        for ip in mem_ips:
            found_in_logs = any(ip in lf.summary for lf in log_network)

            if not found_in_logs:
                results.append(CorrelationResult(
                    check_name="network_activity",
                    finding_a_id=mem_finding.finding_id,
                    finding_b_id="N/A",
                    is_contradiction=True,
                    severity="MEDIUM",
                    description=f"Network connection to {ip} found in memory ({mem_finding.finding_id}) but no corresponding log entry. Possible log tampering or short-lived connection.",
                    follow_up_suggestions=[
                        "Check for event log clearance indicators",
                        "Verify firewall/proxy log coverage for the connection timeframe",
                    ],
                ))

    return results


def check_cross_source_timestamps(findings: list[Finding]) -> list[CorrelationResult]:
    """Cross-check: Timestamps for the same event across different source types.

    Detect clock skew between sources or selective timestamp manipulation.

    Requires findings from multiple source types with overlapping events.
    """
    # This is a more complex check that requires timestamp parsing
    # Implemented as a stub that returns empty results until multi-source data is available
    return []


# Registry of all cross-source checks
CROSS_SOURCE_CHECKS = [
    check_process_existence,
    check_network_activity,
    check_cross_source_timestamps,
]
