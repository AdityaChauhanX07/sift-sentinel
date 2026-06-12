"""Intra-source correlation checks.

These six checks compare findings already in the evidence graph to detect
contradictions (and corroborations) between independent artifact types. They
operate on findings, not raw tool output — post-analysis, not
post-tool-execution. Every check is heuristic: string/regex matching over
summaries and paths. They generate investigation tasks and promotion support,
not final determinations, so some misses and false correlations are acceptable.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass, field

from ..evidence_graph.models import Finding, FindingStatus


@dataclass
class CorrelationResult:
    check_name: str
    finding_a_id: str
    finding_b_id: str
    is_contradiction: bool
    severity: str  # "HIGH", "MEDIUM", "LOW"
    description: str
    follow_up_suggestions: list[str] = field(default_factory=list)


# --- shared helpers ---


def _is_active(finding: Finding) -> bool:
    """Return True if the finding is not ELIMINATED."""
    return finding.status is not FindingStatus.ELIMINATED


def _extract_filename(finding: Finding) -> str | None:
    """Extract the filename from a finding's artifact_path or summary."""
    if finding.evidence_anchor and finding.evidence_anchor.artifact_path:
        path = finding.evidence_anchor.artifact_path
        # Handle both Windows and Unix separators
        parts = re.split(r"[/\\]", path)
        return parts[-1] if parts[-1] else None
    # Fallback: try to find a filename pattern in summary
    match = re.search(r"[\\/]([^\\/\s]+\.\w{1,5})\b", finding.summary)
    if match:
        return match.group(1)
    return None


_TIMESTAMP_RE = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")


def _extract_timestamp(text: str) -> tuple[str, datetime.datetime] | None:
    """Return (raw_string, parsed_datetime) for the first timestamp in text, or None."""
    match = _TIMESTAMP_RE.search(text or "")
    if not match:
        return None
    raw = match.group(1)
    try:
        parsed = datetime.datetime.strptime(raw.replace("T", " "), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return raw, parsed


def _normalize_hash(hash_str: str) -> str:
    """Strip a sha256:/md5: prefix and lowercase a hash string."""
    cleaned = (hash_str or "").strip().lower()
    for prefix in ("sha256:", "md5:"):
        if cleaned.startswith(prefix):
            return cleaned[len(prefix):]
    return cleaned


def _same_filename(a: str | None, b: str | None) -> bool:
    """Case-insensitive filename equality, both non-empty."""
    return bool(a) and bool(b) and a.lower() == b.lower()


# --- check 1: execution verification (Prefetch vs AmCache) ---


def check_execution_verification(findings: list[Finding]) -> list[CorrelationResult]:
    """Cross-check execution evidence: Prefetch vs AmCache.

    If a finding claims program execution based on Prefetch, look for a
    corresponding AmCache entry for the same executable, and vice versa.
    Agreement strengthens both. Disagreement is a contradiction.
    """
    active = [f for f in findings if _is_active(f)]
    prefetch = [
        f
        for f in active
        if f.category == "execution_evidence" or "prefetch" in f.summary.lower()
    ]
    amcache = [
        f
        for f in active
        if f.category == "execution_evidence" or "amcache" in f.summary.lower()
    ]

    results: list[CorrelationResult] = []
    seen_corroboration: set = set()

    for pf in prefetch:
        filename = _extract_filename(pf)
        if not filename:
            continue
        match = next(
            (
                am
                for am in amcache
                if am.finding_id != pf.finding_id
                and _same_filename(_extract_filename(am), filename)
            ),
            None,
        )
        if match is None:
            results.append(
                CorrelationResult(
                    check_name="execution_verification",
                    finding_a_id=pf.finding_id,
                    finding_b_id="",
                    is_contradiction=True,
                    severity="MEDIUM",
                    description=(
                        f"Prefetch shows execution of '{filename}' (finding "
                        f"{pf.finding_id}) but no corresponding AmCache entry found. "
                        f"Either AmCache was cleared, the finding is from a different "
                        f"time window, or the prefetch finding may be incorrectly "
                        f"attributed."
                    ),
                    follow_up_suggestions=[
                        "Check AmCache for temporal gaps suggesting clearance",
                        "Verify prefetch filename matches exactly",
                    ],
                )
            )
        else:
            pair = frozenset({pf.finding_id, match.finding_id})
            if pair in seen_corroboration:
                continue
            seen_corroboration.add(pair)
            results.append(
                CorrelationResult(
                    check_name="execution_verification",
                    finding_a_id=pf.finding_id,
                    finding_b_id=match.finding_id,
                    is_contradiction=False,
                    severity="LOW",
                    description=(
                        f"Execution of '{filename}' corroborated by both Prefetch "
                        f"({pf.finding_id}) and AmCache ({match.finding_id})."
                    ),
                    follow_up_suggestions=[],
                )
            )

    return results


# --- check 2: file existence (MFT vs Prefetch paths) ---


def check_file_existence(findings: list[Finding]) -> list[CorrelationResult]:
    """Cross-check file references: MFT vs Prefetch paths.

    If Prefetch references an executable path, verify that a corresponding
    MFT/filesystem finding confirms the file exists (or existed) at that path.
    """
    active = [f for f in findings if _is_active(f)]
    execution = [
        f
        for f in active
        if (f.category in ("execution_evidence", "prefetch"))
        and f.evidence_anchor
        and f.evidence_anchor.artifact_path
    ]
    mft = [
        f
        for f in active
        if f.category in ("file_artifact", "filesystem")
        or "mft" in f.summary.lower()
        or "timeline" in f.summary.lower()
    ]

    results: list[CorrelationResult] = []
    for ex in execution:
        path = ex.evidence_anchor.artifact_path
        filename = _extract_filename(ex)
        match = next(
            (
                m
                for m in mft
                if m.finding_id != ex.finding_id
                and (
                    (path and m.evidence_anchor and m.evidence_anchor.artifact_path
                     and path.lower() == m.evidence_anchor.artifact_path.lower())
                    or _same_filename(_extract_filename(m), filename)
                )
            ),
            None,
        )
        if match is None:
            results.append(
                CorrelationResult(
                    check_name="file_existence",
                    finding_a_id=ex.finding_id,
                    finding_b_id="",
                    is_contradiction=True,
                    severity="MEDIUM",
                    description=(
                        f"Execution evidence references '{path}' ({ex.finding_id}) but "
                        f"no corresponding MFT/filesystem entry found. File may have "
                        f"been deleted (check USN journal) or the path may be "
                        f"hallucinated."
                    ),
                    follow_up_suggestions=[
                        "Check MFT for deletion record",
                        "Search USN journal for file creation/deletion events",
                    ],
                )
            )
        else:
            results.append(
                CorrelationResult(
                    check_name="file_existence",
                    finding_a_id=ex.finding_id,
                    finding_b_id=match.finding_id,
                    is_contradiction=False,
                    severity="LOW",
                    description=(
                        f"Execution reference '{path}' ({ex.finding_id}) corroborated "
                        f"by MFT/filesystem entry ({match.finding_id})."
                    ),
                    follow_up_suggestions=[],
                )
            )

    return results


# --- check 3: persistence verification (Registry Run keys vs filesystem) ---


_EXE_PATH_RE = re.compile(r"([A-Za-z]:\\[^\s,;\"]+\.exe)")


def check_persistence_verification(findings: list[Finding]) -> list[CorrelationResult]:
    """Cross-check persistence: Registry Run keys vs filesystem.

    If a registry Run key points to an executable path, verify a filesystem
    finding confirms the file exists at that path.
    """
    active = [f for f in findings if _is_active(f)]

    def is_registry(f: Finding) -> bool:
        summary = f.summary.lower()
        if f.category in ("registry_artifact", "persistence"):
            return True
        return "run" in summary and ("registry" in summary or "hk" in summary)

    registry = [f for f in active if is_registry(f)]
    files = [f for f in active if f.category == "file_artifact"]

    results: list[CorrelationResult] = []
    for reg in registry:
        path_match = _EXE_PATH_RE.search(reg.summary)
        if not path_match:
            continue
        exe_path = path_match.group(1)
        exe_filename = re.split(r"[/\\]", exe_path)[-1]
        match = next(
            (
                fa
                for fa in files
                if fa.finding_id != reg.finding_id
                and (
                    (fa.evidence_anchor and fa.evidence_anchor.artifact_path
                     and fa.evidence_anchor.artifact_path.lower() == exe_path.lower())
                    or _same_filename(_extract_filename(fa), exe_filename)
                )
            ),
            None,
        )
        if match is None:
            results.append(
                CorrelationResult(
                    check_name="persistence_verification",
                    finding_a_id=reg.finding_id,
                    finding_b_id="",
                    is_contradiction=True,
                    severity="HIGH",
                    description=(
                        f"Registry persistence at '{reg.finding_id}' points to "
                        f"'{exe_path}' ({reg.finding_id}) but no file artifact found "
                        f"at that location. Possible deleted malware or hallucinated "
                        f"connection."
                    ),
                    follow_up_suggestions=[
                        "Check MFT for file at the referenced path",
                        "Verify registry value raw data in tool output",
                    ],
                )
            )
        else:
            results.append(
                CorrelationResult(
                    check_name="persistence_verification",
                    finding_a_id=reg.finding_id,
                    finding_b_id=match.finding_id,
                    is_contradiction=False,
                    severity="LOW",
                    description=(
                        f"Registry persistence ({reg.finding_id}) pointing to "
                        f"'{exe_path}' corroborated by file artifact "
                        f"({match.finding_id})."
                    ),
                    follow_up_suggestions=[],
                )
            )

    return results


# --- check 4: timestamp consistency (MFT vs Event Log) ---


def check_timestamp_consistency(findings: list[Finding]) -> list[CorrelationResult]:
    """Cross-check timestamps: MFT file creation vs Event Log event times.

    If an event log finding and a file artifact finding reference the same
    entity, their timestamps should be reasonably close. A gap > 1 hour for
    what should be the same event suggests timestomping or wrong correlation.
    """
    active = [f for f in findings if _is_active(f)]
    event_logs = [
        f
        for f in active
        if "event" in f.summary.lower()
        or "evtx" in f.summary.lower()
        or f.category == "event_log"
    ]
    file_artifacts = [f for f in active if f.category == "file_artifact"]

    results: list[CorrelationResult] = []
    seen: set = set()

    for fa in file_artifacts:
        fa_name = _extract_filename(fa)
        if not fa_name:
            continue
        fa_ts = _extract_timestamp(fa.summary)
        if fa_ts is None:
            continue
        for ev in event_logs:
            if ev.finding_id == fa.finding_id:
                continue
            if not _same_filename(_extract_filename(ev), fa_name):
                continue
            pair = frozenset({fa.finding_id, ev.finding_id})
            if pair in seen:
                continue
            ev_ts = _extract_timestamp(ev.summary)
            if ev_ts is None:
                continue
            seen.add(pair)
            diff_seconds = abs((fa_ts[1] - ev_ts[1]).total_seconds())
            if diff_seconds > 3600:
                hours = diff_seconds / 3600
                results.append(
                    CorrelationResult(
                        check_name="timestamp_consistency",
                        finding_a_id=fa.finding_id,
                        finding_b_id=ev.finding_id,
                        is_contradiction=True,
                        severity="MEDIUM",
                        description=(
                            f"Timestamp discrepancy for '{fa_name}': file artifact "
                            f"shows {fa_ts[0]} ({fa.finding_id}) but event log shows "
                            f"{ev_ts[0]} ({ev.finding_id}) — {hours:.1f} hours apart. "
                            f"Possible timestomping or incorrect correlation."
                        ),
                        follow_up_suggestions=[
                            "Check for other timestamp anomalies on the same file",
                            "Compare $STANDARD_INFORMATION vs $FILE_NAME timestamps",
                        ],
                    )
                )
            else:
                results.append(
                    CorrelationResult(
                        check_name="timestamp_consistency",
                        finding_a_id=fa.finding_id,
                        finding_b_id=ev.finding_id,
                        is_contradiction=False,
                        severity="LOW",
                        description=(
                            f"Timestamps for '{fa_name}' corroborate: file artifact "
                            f"{fa_ts[0]} ({fa.finding_id}) and event log {ev_ts[0]} "
                            f"({ev.finding_id}) are within one hour."
                        ),
                        follow_up_suggestions=[],
                    )
                )

    return results


# --- check 5: execution count (Prefetch run count vs Event Log events) ---


_RUN_COUNT_RE = re.compile(r"run\s*count[:\s]*(\d+)", re.IGNORECASE)


def check_execution_count(findings: list[Finding]) -> list[CorrelationResult]:
    """Cross-check execution counts: Prefetch run count vs Event Log execution events.

    Large discrepancies in execution count suggest over- or under-counting.
    This check is inherently fuzzy — prefetch counts total runs over the file's
    lifetime while event logs may only cover a recent window. The 5x threshold
    is deliberately generous.
    """
    active = [f for f in findings if _is_active(f)]
    event_logs = [
        f
        for f in active
        if "event" in f.summary.lower()
        or "evtx" in f.summary.lower()
        or f.category == "event_log"
    ]

    results: list[CorrelationResult] = []
    for pf in active:
        count_match = _RUN_COUNT_RE.search(pf.summary)
        if not count_match:
            continue
        filename = _extract_filename(pf)
        if not filename:
            continue
        prefetch_count = int(count_match.group(1))
        event_count = sum(
            1
            for ev in event_logs
            if ev.finding_id != pf.finding_id
            and _same_filename(_extract_filename(ev), filename)
        )
        # Differ by more than 5x in either direction (event_count 0 counts as a gap).
        diverges = prefetch_count > 5 * event_count or (
            event_count > 0 and event_count > 5 * prefetch_count
        )
        if diverges:
            results.append(
                CorrelationResult(
                    check_name="execution_count",
                    finding_a_id=pf.finding_id,
                    finding_b_id="",
                    is_contradiction=True,
                    severity="LOW",
                    description=(
                        f"Execution count discrepancy for '{filename}': Prefetch run "
                        f"count is {prefetch_count} ({pf.finding_id}) but only "
                        f"{event_count} event log entries found. Large discrepancy may "
                        f"indicate incomplete log coverage or over-counting."
                    ),
                    follow_up_suggestions=[
                        "Check if event logs were cleared",
                        "Verify prefetch run count in raw tool output",
                    ],
                )
            )

    return results


# --- check 6: hash consistency (AmCache hash vs file_artifact hash) ---


def check_hash_consistency(findings: list[Finding]) -> list[CorrelationResult]:
    """Cross-check file hashes: AmCache recorded hash vs computed file hash.

    If AmCache records a hash for a file and a separate file_artifact finding
    has a hash for what should be the same file, they should match.
    """
    active = [f for f in findings if _is_active(f)]
    amcache = [
        f
        for f in active
        if "amcache" in f.summary.lower()
        and f.evidence_anchor
        and f.evidence_anchor.file_hash
    ]
    file_artifacts = [
        f
        for f in active
        if f.category == "file_artifact"
        and f.evidence_anchor
        and f.evidence_anchor.file_hash
    ]

    results: list[CorrelationResult] = []
    seen: set = set()

    for am in amcache:
        am_name = _extract_filename(am)
        if not am_name:
            continue
        for fa in file_artifacts:
            if fa.finding_id == am.finding_id:
                continue
            if not _same_filename(_extract_filename(fa), am_name):
                continue
            pair = frozenset({am.finding_id, fa.finding_id})
            if pair in seen:
                continue
            seen.add(pair)
            hash_a = _normalize_hash(am.evidence_anchor.file_hash)
            hash_b = _normalize_hash(fa.evidence_anchor.file_hash)
            if hash_a != hash_b:
                results.append(
                    CorrelationResult(
                        check_name="hash_consistency",
                        finding_a_id=am.finding_id,
                        finding_b_id=fa.finding_id,
                        is_contradiction=True,
                        severity="HIGH",
                        description=(
                            f"Hash mismatch for '{am_name}': AmCache records "
                            f"{hash_a[:12]}... ({am.finding_id}) but file artifact "
                            f"shows {hash_b[:12]}... ({fa.finding_id}). File may have "
                            f"been modified between execution and imaging, or agent "
                            f"confused two different files."
                        ),
                        follow_up_suggestions=[
                            "Verify both hashes against raw tool output",
                            "Check if multiple versions of the file exist",
                        ],
                    )
                )
            else:
                results.append(
                    CorrelationResult(
                        check_name="hash_consistency",
                        finding_a_id=am.finding_id,
                        finding_b_id=fa.finding_id,
                        is_contradiction=False,
                        severity="LOW",
                        description=(
                            f"Hash for '{am_name}' corroborates: AmCache "
                            f"({am.finding_id}) and file artifact ({fa.finding_id}) "
                            f"both record {hash_a[:12]}..."
                        ),
                        follow_up_suggestions=[],
                    )
                )

    return results
