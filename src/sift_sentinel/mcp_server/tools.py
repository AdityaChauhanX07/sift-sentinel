"""Typed tool wrappers for SIFT Workstation forensic tools.

Each function wraps a specific CLI-based SIFT tool with typed inputs and
structured outputs. There is NO arbitrary shell access: every command is built
explicitly from validated, typed parameters and executed with ``shell=False``.
Every execution is tracked and its raw output preserved for the audit trail,
and every function returns a :class:`ToolResponse`.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import subprocess
import time

from .response_envelope import ToolResponse, create_response, ExecutionTracker
from .injection_defense import scan_for_injection


# --- command execution ---


def _run_command(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
    """Execute a command and return (returncode, stdout, stderr). Never raises."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return 1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except Exception as exc:  # never raise
        return 1, "", str(exc)


# --- shared parsing helpers ---


def _list_csvs(directory: str) -> set:
    try:
        return {
            os.path.join(directory, f)
            for f in os.listdir(directory)
            if f.lower().endswith(".csv")
        }
    except OSError:
        return set()


def _parse_csv_files(paths) -> list[dict]:
    rows: list[dict] = []
    for path in sorted(paths):
        try:
            with open(path, encoding="utf-8", errors="replace", newline="") as fh:
                rows.extend(dict(r) for r in csv.DictReader(fh))
        except OSError:
            continue
    return rows


def _read_text(paths) -> str:
    chunks = []
    for path in sorted(paths):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                chunks.append(fh.read())
        except OSError:
            continue
    return "\n".join(chunks)


def _row_get(row: dict, keys, default: str = "") -> str:
    """Case-insensitive lookup across candidate column names."""
    lowered = {k.lower(): v for k, v in row.items() if k is not None}
    for key in keys:
        val = lowered.get(key.lower())
        if val not in (None, ""):
            return str(val)
    return default


def _to_int(value, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return default


def _classify(rc: int, stderr: str, parsed, tool_binary: str) -> tuple[str, str]:
    """Map a command result to a (status, error_message) pair."""
    if rc == 127:
        return (
            "error",
            f"Tool not found: {tool_binary}. Ensure SIFT Workstation tools are "
            f"installed.",
        )
    if isinstance(stderr, str) and stderr.startswith("Command timed out"):
        return "timeout", stderr
    if rc != 0:
        return "error", (stderr.strip() if stderr else "Tool returned a non-zero exit code.")
    if not parsed:
        return "no_results", ""
    return "success", ""


def _finalize(
    tool: str,
    execution_id: str,
    input_params: dict,
    status: str,
    raw_output: str,
    raw_output_dir: str,
    parsed_output,
    tracker: ExecutionTracker,
    evidence_hashes: dict | None = None,
    normalized_fields: dict | None = None,
    error_message: str = "",
    duration_seconds: float = 0.0,
) -> ToolResponse:
    """Build, record, and return a ToolResponse."""
    response = create_response(
        tool=tool,
        execution_id=execution_id,
        input_params=input_params,
        status=status,
        raw_output=raw_output,
        raw_output_dir=raw_output_dir,
        parsed_output=parsed_output,
        evidence_hashes=evidence_hashes,
        normalized_fields=normalized_fields,
        error_message=error_message,
        duration_seconds=duration_seconds,
    )
    tracker.record(response)
    return response


def _find_first(candidates) -> str | None:
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def _injection_scan_block(content: str, file_path: str) -> dict:
    """Scan evidence content for prompt injection and build the report block.

    Returns the ``injection_scan`` sub-dict attached to a tool's parsed output.
    A detected injection is itself a forensic finding — the attacker may be
    trying to manipulate automated analysis.
    """
    result = scan_for_injection(content, file_path)
    if not result.injection_detected:
        return {"detected": False}
    return {
        "detected": True,
        "match_count": len(result.matches),
        "patterns_found": list(set(m["pattern"] for m in result.matches)),
        "note": (
            "Prompt injection strings detected in evidence. This is a forensic "
            "finding — the attacker may be attempting to manipulate automated "
            "analysis tools."
        ),
    }


# --- MFT timeline ---


def extract_mft_timeline(
    image_mount_path: str,
    tracker: ExecutionTracker,
    raw_output_dir: str,
    time_range_start: str | None = None,
    time_range_end: str | None = None,
    evidence_hashes: dict | None = None,
) -> ToolResponse:
    """Extract and parse the $MFT from a mounted NTFS image (analyzeMFT, MFTECmd fallback)."""
    execution_id = tracker.next_id()
    start = time.perf_counter()
    input_params = {
        "image_mount_path": image_mount_path,
        "time_range_start": time_range_start,
        "time_range_end": time_range_end,
    }

    mft_path = _find_first(
        [
            os.path.join(image_mount_path, "$MFT"),
            os.path.join(image_mount_path, "Windows", "$MFT"),
        ]
    )
    if mft_path is None:
        return _finalize(
            "extract_mft_timeline", execution_id, input_params, "error", "",
            raw_output_dir, [], tracker, evidence_hashes,
            error_message=f"$MFT not found under {image_mount_path}.",
            duration_seconds=time.perf_counter() - start,
        )

    temp_csv = os.path.join(raw_output_dir, f"{execution_id}_mft.csv")
    os.makedirs(raw_output_dir, exist_ok=True)
    tool_binary = "analyzeMFT"
    rc, stdout, stderr = _run_command(
        ["analyzeMFT", "-f", mft_path, "-o", temp_csv, "--csv"]
    )

    before = _list_csvs(raw_output_dir)
    if rc == 127:
        tool_binary = "MFTECmd"
        before = _list_csvs(raw_output_dir)
        rc, stdout, stderr = _run_command(
            ["MFTECmd", "-f", mft_path, "--csv", raw_output_dir]
        )

    # Locate CSV output: the explicit temp file or any newly created CSV.
    csv_paths = []
    if os.path.isfile(temp_csv):
        csv_paths = [temp_csv]
    else:
        csv_paths = sorted(_list_csvs(raw_output_dir) - before)
    rows = _parse_csv_files(csv_paths)
    raw_output = _read_text(csv_paths) or stdout or stderr

    parsed = []
    for row in rows:
        entry = {
            "record_number": _row_get(row, ["Record Number", "RecordNumber", "EntryNumber"]),
            "filename": _row_get(row, ["Filename", "FileName", "File Name", "Name"]),
            "timestamp_si_created": _row_get(
                row, ["SI Creation", "Std Info Creation date", "Created0x10", "Created"]
            ),
            "timestamp_si_modified": _row_get(
                row, ["SI Modification", "Std Info Modification date", "LastModified0x10", "Modified"]
            ),
            "timestamp_fn_created": _row_get(
                row, ["FN Creation", "File Name Creation date", "Created0x30"]
            ),
            "timestamp_fn_modified": _row_get(
                row, ["FN Modification", "File Name Modification date", "LastModified0x30"]
            ),
            "path": _row_get(row, ["Path", "FullPath", "ParentPath"]),
            "is_directory": _row_get(row, ["Is Directory", "IsDirectory"]).lower()
            in ("true", "1", "yes"),
            "size": _row_get(row, ["Size", "FileSize"]),
        }
        parsed.append(entry)

    # Optional time-range filtering on the SI creation timestamp (lexical ISO compare).
    if time_range_start or time_range_end:
        def in_range(ts: str) -> bool:
            if not ts:
                return False
            if time_range_start and ts < time_range_start:
                return False
            if time_range_end and ts > time_range_end:
                return False
            return True

        parsed = [e for e in parsed if in_range(e["timestamp_si_created"])]

    status, err = _classify(rc, stderr, parsed, tool_binary)
    return _finalize(
        "extract_mft_timeline", execution_id, input_params, status, raw_output,
        raw_output_dir, parsed, tracker, evidence_hashes,
        normalized_fields={"timestamps_format": "tool-native"},
        error_message=err, duration_seconds=time.perf_counter() - start,
    )


# --- Prefetch ---


def parse_prefetch(
    image_mount_path: str,
    tracker: ExecutionTracker,
    raw_output_dir: str,
    filename_filter: str | None = None,
    evidence_hashes: dict | None = None,
) -> ToolResponse:
    """Parse Windows Prefetch files using PECmd."""
    execution_id = tracker.next_id()
    start = time.perf_counter()
    input_params = {"image_mount_path": image_mount_path, "filename_filter": filename_filter}

    prefetch_dir = os.path.join(image_mount_path, "Windows", "Prefetch")
    if not os.path.isdir(prefetch_dir):
        return _finalize(
            "parse_prefetch", execution_id, input_params, "error", "",
            raw_output_dir, [], tracker, evidence_hashes,
            error_message=f"Prefetch directory not found at {prefetch_dir}.",
            duration_seconds=time.perf_counter() - start,
        )

    os.makedirs(raw_output_dir, exist_ok=True)
    before = _list_csvs(raw_output_dir)
    rc, stdout, stderr = _run_command(
        ["PECmd", "-d", prefetch_dir, "--csv", raw_output_dir, "-q"]
    )
    csv_paths = sorted(_list_csvs(raw_output_dir) - before)
    rows = _parse_csv_files(csv_paths)
    raw_output = _read_text(csv_paths) or stdout or stderr

    parsed = []
    for row in rows:
        previous = [
            _row_get(row, [f"PreviousRun{i}"])
            for i in range(7)
        ]
        parsed.append(
            {
                "executable_name": _row_get(row, ["ExecutableName", "Executable"]),
                "run_count": _to_int(_row_get(row, ["RunCount"])),
                "last_run_time": _row_get(row, ["LastRun", "LastRunTime"]),
                "previous_run_times": [p for p in previous if p],
                "source_file": _row_get(row, ["SourceFilename", "SourceFile"]),
                "volume_path": _row_get(row, ["VolumePath", "Volume0Name"]),
            }
        )

    if filename_filter:
        flt = filename_filter.lower()
        parsed = [e for e in parsed if flt in e["executable_name"].lower()]

    status, err = _classify(rc, stderr, parsed, "PECmd")
    return _finalize(
        "parse_prefetch", execution_id, input_params, status, raw_output,
        raw_output_dir, parsed, tracker, evidence_hashes,
        error_message=err, duration_seconds=time.perf_counter() - start,
    )


# --- Registry hive ---


_KV_RE = re.compile(r"^\s*(.+?)\s*(?:=|:|->)\s*(.+?)\s*$")


def _parse_regripper(text: str) -> list[dict]:
    """Best-effort parse of RegRipper text output into plugin sections."""
    if not text.strip():
        return []
    # Split on plugin launch markers when present, else treat as one block.
    markers = re.split(r"(?im)^Launching\s+", text)
    blocks = markers[1:] if len(markers) > 1 else [text]
    sections = []
    for block in blocks:
        lines = block.splitlines()
        if not lines:
            continue
        header = lines[0].strip()
        plugin_name = header.split()[0] if header else ""
        key_values = []
        for line in lines[1:]:
            m = _KV_RE.match(line)
            if m:
                key_values.append({"key": m.group(1).strip(), "value": m.group(2).strip()})
        sections.append(
            {
                "plugin_name": plugin_name,
                "description": header,
                "output": block.strip(),
                "key_values": key_values,
            }
        )
    return sections


def analyze_registry_hive(
    hive_path: str,
    tracker: ExecutionTracker,
    raw_output_dir: str,
    plugin: str | None = None,
    evidence_hashes: dict | None = None,
) -> ToolResponse:
    """Analyze a Windows registry hive using RegRipper (rip)."""
    execution_id = tracker.next_id()
    start = time.perf_counter()
    input_params = {"hive_path": hive_path, "plugin": plugin}

    if not os.path.isfile(hive_path):
        return _finalize(
            "analyze_registry_hive", execution_id, input_params, "error", "",
            raw_output_dir, [], tracker, evidence_hashes,
            error_message=f"Registry hive not found at {hive_path}.",
            duration_seconds=time.perf_counter() - start,
        )

    cmd = ["rip", "-r", hive_path]
    cmd += ["-p", plugin] if plugin else ["-a"]
    rc, stdout, stderr = _run_command(cmd)
    raw_output = stdout or stderr
    sections = _parse_regripper(stdout)

    # Classify on the parsed sections (preserves no_results detection) before
    # wrapping them alongside the injection scan.
    status, err = _classify(rc, stderr, sections, "rip")

    # Registry values are a documented prompt-injection vector — scan the
    # combined section text for manipulation attempts targeting the analyst.
    combined = "\n".join(s.get("output", "") for s in sections)
    parsed = {
        "sections": sections,
        "injection_scan": _injection_scan_block(combined, hive_path),
    }

    return _finalize(
        "analyze_registry_hive", execution_id, input_params, status, raw_output,
        raw_output_dir, parsed, tracker, evidence_hashes,
        error_message=err, duration_seconds=time.perf_counter() - start,
    )


# --- Event logs ---


def parse_event_logs(
    evtx_path: str,
    tracker: ExecutionTracker,
    raw_output_dir: str,
    event_id_filter: list[int] | None = None,
    evidence_hashes: dict | None = None,
) -> ToolResponse:
    """Parse Windows Event Log (.evtx) files using EvtxECmd."""
    execution_id = tracker.next_id()
    start = time.perf_counter()
    input_params = {"evtx_path": evtx_path, "event_id_filter": event_id_filter}

    if not os.path.exists(evtx_path):
        return _finalize(
            "parse_event_logs", execution_id, input_params, "error", "",
            raw_output_dir, [], tracker, evidence_hashes,
            error_message=f"EVTX path not found at {evtx_path}.",
            duration_seconds=time.perf_counter() - start,
        )

    os.makedirs(raw_output_dir, exist_ok=True)
    before = _list_csvs(raw_output_dir)
    rc, stdout, stderr = _run_command(
        ["EvtxECmd", "-f", evtx_path, "--csv", raw_output_dir, "-q"]
    )
    csv_paths = sorted(_list_csvs(raw_output_dir) - before)
    rows = _parse_csv_files(csv_paths)
    raw_output = _read_text(csv_paths) or stdout or stderr

    parsed = []
    for row in rows:
        parsed.append(
            {
                "event_id": _to_int(_row_get(row, ["EventId", "Event ID"])),
                "timestamp": _row_get(row, ["TimeCreated", "Timestamp"]),
                "provider": _row_get(row, ["Provider", "ProviderName"]),
                "channel": _row_get(row, ["Channel"]),
                "computer": _row_get(row, ["Computer", "ComputerName"]),
                "user": _row_get(row, ["UserName", "UserId", "User"]),
                "payload": _row_get(row, ["Payload", "MapDescription"]),
                "record_id": _row_get(row, ["RecordNumber", "EventRecordId"]),
            }
        )

    if event_id_filter:
        wanted = set(event_id_filter)
        parsed = [e for e in parsed if e["event_id"] in wanted]

    status, err = _classify(rc, stderr, parsed, "EvtxECmd")
    return _finalize(
        "parse_event_logs", execution_id, input_params, status, raw_output,
        raw_output_dir, parsed, tracker, evidence_hashes,
        error_message=err, duration_seconds=time.perf_counter() - start,
    )


# --- AmCache ---


def extract_amcache(
    image_mount_path: str,
    tracker: ExecutionTracker,
    raw_output_dir: str,
    evidence_hashes: dict | None = None,
) -> ToolResponse:
    """Extract and parse AmCache.hve entries (AmcacheParser, regripper fallback)."""
    execution_id = tracker.next_id()
    start = time.perf_counter()
    input_params = {"image_mount_path": image_mount_path}

    amcache_path = _find_first(
        [
            os.path.join(
                image_mount_path, "Windows", "AppCompat", "Programs", "Amcache.hve"
            )
        ]
    )
    if amcache_path is None:
        return _finalize(
            "extract_amcache", execution_id, input_params, "error", "",
            raw_output_dir, [], tracker, evidence_hashes,
            error_message=f"Amcache.hve not found under {image_mount_path}.",
            duration_seconds=time.perf_counter() - start,
        )

    os.makedirs(raw_output_dir, exist_ok=True)
    before = _list_csvs(raw_output_dir)
    tool_binary = "AmcacheParser"
    rc, stdout, stderr = _run_command(
        ["AmcacheParser", "-f", amcache_path, "--csv", raw_output_dir]
    )
    csv_paths = sorted(_list_csvs(raw_output_dir) - before)

    if rc == 127:
        tool_binary = "rip"
        rc, stdout, stderr = _run_command(
            ["rip", "-r", amcache_path, "-p", "amcache"]
        )

    rows = _parse_csv_files(csv_paths)
    raw_output = _read_text(csv_paths) or stdout or stderr

    parsed = []
    for row in rows:
        parsed.append(
            {
                "file_name": _row_get(row, ["Name", "FileName", "ApplicationName"]),
                "file_path": _row_get(row, ["FullPath", "Path"]),
                "sha1_hash": _row_get(row, ["SHA1", "Sha1"]),
                "last_modified": _row_get(
                    row, ["FileKeyLastWriteTimestamp", "LastModified", "LastWrite"]
                ),
                "program_name": _row_get(row, ["ProductName", "ProgramName"]),
                "publisher": _row_get(row, ["Publisher", "CompanyName"]),
                "install_date": _row_get(row, ["InstallDate"]),
            }
        )

    status, err = _classify(rc, stderr, parsed, tool_binary)
    return _finalize(
        "extract_amcache", execution_id, input_params, status, raw_output,
        raw_output_dir, parsed, tracker, evidence_hashes,
        error_message=err, duration_seconds=time.perf_counter() - start,
    )


# --- File hash (pure Python) ---


def compute_file_hash(
    file_path: str,
    tracker: ExecutionTracker,
    raw_output_dir: str,
) -> ToolResponse:
    """Compute SHA-256 (and MD5) of a file. Pure Python, no external tool."""
    execution_id = tracker.next_id()
    start = time.perf_counter()
    input_params = {"file_path": file_path}

    if not os.path.isfile(file_path):
        return _finalize(
            "compute_file_hash", execution_id, input_params, "error", "",
            raw_output_dir, None, tracker,
            error_message=f"File not found or not a regular file: {file_path}.",
            duration_seconds=time.perf_counter() - start,
        )

    try:
        sha = hashlib.sha256()
        md5 = hashlib.md5()
        size = 0
        with open(file_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(8192), b""):
                sha.update(chunk)
                md5.update(chunk)
                size += len(chunk)
    except OSError as exc:
        return _finalize(
            "compute_file_hash", execution_id, input_params, "error", "",
            raw_output_dir, None, tracker,
            error_message=f"Failed to read {file_path}: {exc}",
            duration_seconds=time.perf_counter() - start,
        )

    parsed = {
        "file_path": file_path,
        "sha256": "sha256:" + sha.hexdigest(),
        "md5": "md5:" + md5.hexdigest(),
        "file_size": size,
    }
    raw_output = json.dumps(parsed, indent=2)
    return _finalize(
        "compute_file_hash", execution_id, input_params, "success", raw_output,
        raw_output_dir, parsed, tracker,
        normalized_fields={"hash_algorithms": "sha256,md5"},
        duration_seconds=time.perf_counter() - start,
    )


# --- Strings ---


def extract_strings(
    file_path: str,
    tracker: ExecutionTracker,
    raw_output_dir: str,
    min_length: int = 6,
    encoding: str = "both",
    evidence_hashes: dict | None = None,
) -> ToolResponse:
    """Extract ASCII/Unicode strings from a binary file using GNU strings."""
    execution_id = tracker.next_id()
    start = time.perf_counter()
    input_params = {"file_path": file_path, "min_length": min_length, "encoding": encoding}

    if not os.path.isfile(file_path):
        return _finalize(
            "extract_strings", execution_id, input_params, "error", "",
            raw_output_dir, None, tracker, evidence_hashes,
            error_message=f"File not found or not a regular file: {file_path}.",
            duration_seconds=time.perf_counter() - start,
        )

    n = str(min_length)
    raw_chunks = []
    rc = 0
    stderr = ""
    tool_binary = "strings"

    if encoding in ("ascii", "both"):
        rc_a, out_a, err_a = _run_command(["strings", "-n", n, file_path])
        raw_chunks.append(out_a)
        rc, stderr = rc_a, err_a
    if encoding in ("unicode", "both"):
        rc_u, out_u, err_u = _run_command(["strings", "-n", n, "-el", file_path])
        raw_chunks.append(out_u)
        # Surface a failure from either invocation.
        if rc == 0 and rc_u != 0:
            rc, stderr = rc_u, err_u

    raw_output = "\n".join(c for c in raw_chunks if c)

    # Deduplicate, preserving first-seen order.
    seen = set()
    unique = []
    for line in raw_output.splitlines():
        s = line.strip()
        if s and s not in seen:
            seen.add(s)
            unique.append(s)

    total = len(unique)
    truncated = total > 1000
    parsed = {
        "file_path": file_path,
        "encoding": encoding,
        "total_strings": total,
        "strings": unique[:1000],
        "truncated": truncated,
    }

    # Scan the extracted strings for prompt injection attempts targeting the
    # analyst. A hit is a suspicious artifact worth investigating, not a gate.
    parsed["injection_scan"] = _injection_scan_block("\n".join(unique), file_path)

    if rc == 127:
        status, err = "error", (
            "Tool not found: strings. Ensure SIFT Workstation tools are installed."
        )
    elif isinstance(stderr, str) and stderr.startswith("Command timed out"):
        status, err = "timeout", stderr
    elif rc != 0:
        status, err = "error", (stderr.strip() if stderr else "strings returned non-zero.")
    elif total == 0:
        status, err = "no_results", ""
    else:
        status, err = "success", ""

    return _finalize(
        "extract_strings", execution_id, input_params, status, raw_output,
        raw_output_dir, parsed, tracker, evidence_hashes,
        error_message=err, duration_seconds=time.perf_counter() - start,
    )


# --- Volatility 3 helpers (shared by the memory analysis tools) ---


def _run_volatility(memory_image_path: str, plugin: str) -> tuple[int, str, str]:
    """Run a Volatility 3 plugin, trying the global ``vol`` then ``python3 -m volatility3``."""
    rc, out, err = _run_command(
        ["vol", "-f", memory_image_path, plugin, "--output", "json"]
    )
    if rc == 127:
        rc, out, err = _run_command(
            ["python3", "-m", "volatility3", "-f", memory_image_path, plugin,
             "--output", "json"]
        )
    return rc, out, err


def _parse_vol_json(stdout: str):
    """Parse Volatility JSON output into a list of row dicts, or None if not JSON."""
    s = stdout.strip()
    if not s:
        return None
    try:
        data = json.loads(s)
    except (ValueError, TypeError):
        return None
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        # Some renderers wrap the rows under a key; take the first list value.
        for value in data.values():
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
        return [data]
    return None


def _parse_vol_table(text: str, header_hints) -> list[dict]:
    """Best-effort parse of Volatility's tabular text output into row dicts.

    Locates the header row by matching at least two of ``header_hints``, then
    splits columns on tabs (preferred) or runs of two-or-more spaces.
    """
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return []
    hints = [h.lower() for h in header_hints]

    header_idx = None
    for i, ln in enumerate(lines):
        low = ln.lower()
        if sum(1 for h in hints if h in low) >= 2:
            header_idx = i
            break
    if header_idx is None:
        return []

    def split_cols(line: str) -> list[str]:
        if "\t" in line:
            return [c.strip() for c in line.split("\t")]
        return [c.strip() for c in re.split(r"\s{2,}", line.strip())]

    headers = split_cols(lines[header_idx])
    rows: list[dict] = []
    for ln in lines[header_idx + 1:]:
        cols = split_cols(ln)
        if len(cols) < 2:
            continue
        rows.append(
            {h: (cols[j] if j < len(cols) else "") for j, h in enumerate(headers)}
        )
    return rows


# --- Memory: process list (Volatility 3 windows.pslist / pstree) ---


def analyze_memory_processes(
    memory_image_path: str,
    tracker: ExecutionTracker,
    raw_output_dir: str,
    evidence_hashes: dict | None = None,
) -> ToolResponse:
    """List running processes from a memory capture using Volatility 3."""
    execution_id = tracker.next_id()
    start = time.perf_counter()
    input_params = {"memory_image_path": memory_image_path}

    if not os.path.isfile(memory_image_path):
        return _finalize(
            "analyze_memory_processes", execution_id, input_params, "error", "",
            raw_output_dir, [], tracker, evidence_hashes,
            error_message=f"Memory image not found or not a regular file: "
            f"{memory_image_path}.",
            duration_seconds=time.perf_counter() - start,
        )

    rc, stdout, stderr = _run_volatility(memory_image_path, "windows.pslist")
    raw_output = stdout or stderr

    rows = _parse_vol_json(stdout)
    if rows is None:
        rows = _parse_vol_table(stdout, ["PID", "PPID", "ImageFileName"])

    parsed = []
    for row in rows:
        parsed.append(
            {
                "pid": _to_int(_row_get(row, ["PID", "Pid"])),
                "ppid": _to_int(_row_get(row, ["PPID", "Ppid"])),
                "image_name": _row_get(row, ["ImageFileName", "Image", "Name"]),
                "offset": _row_get(row, ["Offset(V)", "Offset", "Offset(P)"]),
                "threads": _to_int(_row_get(row, ["Threads"])),
                "handles": _to_int(_row_get(row, ["Handles"])),
                "session_id": _to_int(_row_get(row, ["SessionId", "Session"])),
                "create_time": _row_get(row, ["CreateTime", "Created"]),
                "exit_time": _row_get(row, ["ExitTime", "Exited"]),
            }
        )

    status, err = _classify(rc, stderr, parsed, "volatility3")
    return _finalize(
        "analyze_memory_processes", execution_id, input_params, status, raw_output,
        raw_output_dir, parsed, tracker, evidence_hashes,
        error_message=err, duration_seconds=time.perf_counter() - start,
    )


# --- Memory: network connections (Volatility 3 windows.netscan) ---


def analyze_memory_network(
    memory_image_path: str,
    tracker: ExecutionTracker,
    raw_output_dir: str,
    evidence_hashes: dict | None = None,
) -> ToolResponse:
    """Extract network connections from a memory capture using Volatility 3."""
    execution_id = tracker.next_id()
    start = time.perf_counter()
    input_params = {"memory_image_path": memory_image_path}

    if not os.path.isfile(memory_image_path):
        return _finalize(
            "analyze_memory_network", execution_id, input_params, "error", "",
            raw_output_dir, [], tracker, evidence_hashes,
            error_message=f"Memory image not found or not a regular file: "
            f"{memory_image_path}.",
            duration_seconds=time.perf_counter() - start,
        )

    rc, stdout, stderr = _run_volatility(memory_image_path, "windows.netscan")
    raw_output = stdout or stderr

    rows = _parse_vol_json(stdout)
    if rows is None:
        rows = _parse_vol_table(stdout, ["Proto", "LocalAddr", "PID"])

    parsed = []
    for row in rows:
        parsed.append(
            {
                "protocol": _row_get(row, ["Proto", "Protocol"]),
                "local_address": _row_get(row, ["LocalAddr", "LocalAddress", "Local Address"]),
                "local_port": _to_int(_row_get(row, ["LocalPort", "Local Port"])),
                "remote_address": _row_get(
                    row, ["ForeignAddr", "RemoteAddress", "Foreign Address"]
                ),
                "remote_port": _to_int(
                    _row_get(row, ["ForeignPort", "RemotePort", "Foreign Port"])
                ),
                "state": _row_get(row, ["State"]),
                "pid": _to_int(_row_get(row, ["PID", "Pid"])),
                "owner": _row_get(row, ["Owner"]),
                "created": _row_get(row, ["Created", "CreateTime"]),
            }
        )

    status, err = _classify(rc, stderr, parsed, "volatility3")
    return _finalize(
        "analyze_memory_network", execution_id, input_params, status, raw_output,
        raw_output_dir, parsed, tracker, evidence_hashes,
        error_message=err, duration_seconds=time.perf_counter() - start,
    )


# --- Memory: injected-code detection (Volatility 3 windows.malfind) ---


def analyze_memory_malfind(
    memory_image_path: str,
    tracker: ExecutionTracker,
    raw_output_dir: str,
    evidence_hashes: dict | None = None,
) -> ToolResponse:
    """Detect potentially injected code in process memory using Volatility 3."""
    execution_id = tracker.next_id()
    start = time.perf_counter()
    input_params = {"memory_image_path": memory_image_path}

    if not os.path.isfile(memory_image_path):
        return _finalize(
            "analyze_memory_malfind", execution_id, input_params, "error", "",
            raw_output_dir, [], tracker, evidence_hashes,
            error_message=f"Memory image not found or not a regular file: "
            f"{memory_image_path}.",
            duration_seconds=time.perf_counter() - start,
        )

    rc, stdout, stderr = _run_volatility(memory_image_path, "windows.malfind")
    raw_output = stdout or stderr

    rows = _parse_vol_json(stdout)
    if rows is None:
        rows = _parse_vol_table(stdout, ["PID", "Process", "Protection"])

    parsed = []
    for row in rows:
        parsed.append(
            {
                "pid": _to_int(_row_get(row, ["PID", "Pid"])),
                "process_name": _row_get(row, ["Process", "ImageFileName", "Name"]),
                "address": _row_get(
                    row, ["Start VPN", "Address", "Start", "StartVPN"]
                ),
                "vad_tag": _row_get(row, ["Tag", "VadTag", "Vad Tag"]),
                "protection": _row_get(row, ["Protection"]),
                "hexdump": _row_get(row, ["Hexdump", "HexDump"]),
                "disassembly": _row_get(row, ["Disasm", "Disassembly"]),
            }
        )

    status, err = _classify(rc, stderr, parsed, "volatility3")
    return _finalize(
        "analyze_memory_malfind", execution_id, input_params, status, raw_output,
        raw_output_dir, parsed, tracker, evidence_hashes,
        error_message=err, duration_seconds=time.perf_counter() - start,
    )


# --- LNK shortcut files (LECmd) ---


def parse_lnk_files(
    image_mount_path: str,
    tracker: ExecutionTracker,
    raw_output_dir: str,
    evidence_hashes: dict | None = None,
) -> ToolResponse:
    """Parse Windows LNK (shortcut) files using LECmd."""
    execution_id = tracker.next_id()
    start = time.perf_counter()
    input_params = {"image_mount_path": image_mount_path}

    if not os.path.isdir(image_mount_path):
        return _finalize(
            "parse_lnk_files", execution_id, input_params, "error", "",
            raw_output_dir, [], tracker, evidence_hashes,
            error_message=f"Image mount path not found: {image_mount_path}.",
            duration_seconds=time.perf_counter() - start,
        )

    # Bounded recursive search for *.lnk files (cap at 500 to protect the budget).
    lnk_files: list[str] = []
    for root, _dirs, files in os.walk(image_mount_path):
        for fn in files:
            if fn.lower().endswith(".lnk"):
                lnk_files.append(os.path.join(root, fn))
                if len(lnk_files) >= 500:
                    break
        if len(lnk_files) >= 500:
            break

    if not lnk_files:
        return _finalize(
            "parse_lnk_files", execution_id, input_params, "no_results", "",
            raw_output_dir, [], tracker, evidence_hashes,
            error_message="",
            duration_seconds=time.perf_counter() - start,
        )

    os.makedirs(raw_output_dir, exist_ok=True)
    # Process the unique directories that directly contain LNK files (LECmd -d).
    # Cap the number of directories to keep subprocess count bounded.
    lnk_dirs = sorted({os.path.dirname(p) for p in lnk_files})[:50]
    before = _list_csvs(raw_output_dir)
    rc, stdout, stderr = 127, "", ""
    for d in lnk_dirs:
        rc, stdout, stderr = _run_command(["LECmd", "-d", d, "--csv", raw_output_dir, "-q"])
        if rc == 127:
            break  # tool unavailable — no point retrying on other directories

    csv_paths = sorted(_list_csvs(raw_output_dir) - before)
    rows = _parse_csv_files(csv_paths)
    raw_output = _read_text(csv_paths) or stdout or stderr

    parsed = []
    for row in rows:
        parsed.append(
            {
                "source_file": _row_get(row, ["SourceFile", "SourceFilename", "Source File"]),
                "target_path": _row_get(
                    row, ["LocalPath", "TargetIDAbsolutePath", "AbsolutePath", "CommonPath"]
                ),
                "target_created": _row_get(row, ["TargetCreated", "Target Created"]),
                "target_modified": _row_get(row, ["TargetModified", "Target Modified"]),
                "target_accessed": _row_get(row, ["TargetAccessed", "Target Accessed"]),
                "file_size": _to_int(_row_get(row, ["FileSize", "File Size"])),
                "relative_path": _row_get(row, ["RelativePath", "Relative Path"]),
                "working_directory": _row_get(row, ["WorkingDirectory", "Working Directory"]),
                "arguments": _row_get(row, ["Arguments"]),
                "drive_type": _row_get(row, ["DriveType", "Drive Type"]),
                "volume_label": _row_get(row, ["VolumeLabel", "Volume Label"]),
                "volume_serial": _row_get(
                    row, ["VolumeSerialNumber", "VolumeSerial", "Volume Serial Number"]
                ),
            }
        )

    status, err = _classify(rc, stderr, parsed, "LECmd")
    return _finalize(
        "parse_lnk_files", execution_id, input_params, status, raw_output,
        raw_output_dir, parsed, tracker, evidence_hashes,
        error_message=err, duration_seconds=time.perf_counter() - start,
    )


# --- NTFS USN Journal (MFTECmd in USN mode) ---


def analyze_usn_journal(
    image_mount_path: str,
    tracker: ExecutionTracker,
    raw_output_dir: str,
    filename_filter: str | None = None,
    evidence_hashes: dict | None = None,
) -> ToolResponse:
    """Parse the NTFS USN ($UsnJrnl:$J) journal for file change records using MFTECmd."""
    execution_id = tracker.next_id()
    start = time.perf_counter()
    input_params = {"image_mount_path": image_mount_path, "filename_filter": filename_filter}

    usn_path = _find_first(
        [
            os.path.join(image_mount_path, "$Extend", "$UsnJrnl:$J"),
            os.path.join(image_mount_path, "$Extend", "$UsnJrnl"),
            os.path.join(image_mount_path, "$UsnJrnl:$J"),
            os.path.join(image_mount_path, "$UsnJrnl"),
        ]
    )
    if usn_path is None:
        return _finalize(
            "analyze_usn_journal", execution_id, input_params, "error", "",
            raw_output_dir, [], tracker, evidence_hashes,
            error_message=f"$UsnJrnl:$J not found under {image_mount_path}.",
            duration_seconds=time.perf_counter() - start,
        )

    os.makedirs(raw_output_dir, exist_ok=True)
    before = _list_csvs(raw_output_dir)
    # MFTECmd USN mode. (A pure-Python USN parser would be the fallback if MFTECmd
    # is unavailable; none is bundled, so a missing tool surfaces as an error.)
    rc, stdout, stderr = _run_command(
        ["MFTECmd", "-f", usn_path, "--csv", raw_output_dir, "--fl", "usn"]
    )
    csv_paths = sorted(_list_csvs(raw_output_dir) - before)
    # _parse_csv_files streams each row via csv.DictReader, so large journals are
    # read incrementally rather than loaded whole.
    rows = _parse_csv_files(csv_paths)
    raw_output = _read_text(csv_paths) or stdout or stderr

    parsed = []
    for row in rows:
        parent_path = _row_get(row, ["ParentPath", "Parent Path"])
        filename = _row_get(row, ["Name", "FileName", "File Name"])
        full_path = _row_get(row, ["FullPath", "Full Path", "Path"])
        if not full_path and parent_path:
            full_path = (
                parent_path.rstrip("\\/") + "\\" + filename if filename else parent_path
            )
        usn_raw = _row_get(row, ["UpdateSequenceNumber", "Usn", "USN"])
        parsed.append(
            {
                "timestamp": _row_get(row, ["UpdateTimestamp", "Timestamp", "UpdateTime"]),
                "filename": filename,
                "full_path": full_path,
                "reason": _row_get(
                    row, ["UpdateReasons", "Reason", "Reasons", "UpdateReason"]
                ),
                "file_attributes": _row_get(row, ["FileAttributes", "File Attributes"]),
                "source_info": _row_get(row, ["SourceFile", "SourceInfo", "Source"]),
                "usn": _to_int(usn_raw),
                "parent_path": parent_path,
                "update_sequence_number": usn_raw,
            }
        )

    if filename_filter:
        flt = filename_filter.lower()
        parsed = [e for e in parsed if flt in e["filename"].lower()]

    status, err = _classify(rc, stderr, parsed, "MFTECmd")
    return _finalize(
        "analyze_usn_journal", execution_id, input_params, status, raw_output,
        raw_output_dir, parsed, tracker, evidence_hashes,
        error_message=err, duration_seconds=time.perf_counter() - start,
    )
