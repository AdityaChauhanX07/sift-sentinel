import sys
sys.path.insert(0, '/home/aditya/sift-sentinel/src')

from sift_sentinel.evidence_graph.models import *
from sift_sentinel.evidence_graph.graph import EvidenceGraphManager
from sift_sentinel.validators import create_default_pipeline
from sift_sentinel.evidence_graph.models import ValidatorVerdict

graph_path = '/home/aditya/sentinel-output/evidence_graph.json'
mgr = EvidenceGraphManager.load(graph_path)

# Register new evidence sources: Prefetch directory listing and EventLogs
src_pf = mgr.add_source(
    source_type="prefetch_directory",
    path="~/cases/mini-case/Prefetch/",
    sha256="N/A-directory-listing",
    mounted_at="~/cases/mini-case/Prefetch/",
    metadata={"file_count": 500, "unique_programs": 268, "tool": "ls", "exec_id": "exec-pf-list"},
)
src_evtx_sys = mgr.add_source(
    source_type="event_log",
    path="~/cases/mini-case/EventLogs/System.evtx",
    sha256="N/A-strings-extraction",
    mounted_at="~/cases/mini-case/EventLogs/System.evtx",
    metadata={"tool": "strings -el", "exec_id": "exec-evtx-system"},
)
src_evtx_sec = mgr.add_source(
    source_type="event_log",
    path="~/cases/mini-case/EventLogs/Security.evtx",
    sha256="N/A-strings-extraction",
    mounted_at="~/cases/mini-case/EventLogs/Security.evtx",
    metadata={"tool": "strings -el", "exec_id": "exec-evtx-security"},
)

# --- F-008: Cluely (stealth AI assistant) executed ---
f8 = mgr.add_finding(
    summary=(
        "Prefetch evidence shows CLUELY.EXE was executed on this host "
        "(C:\\Windows\\Prefetch\\CLUELY.EXE-333AB11B.pf present). 'Cluely' is a "
        "commercially marketed AI assistant explicitly designed to run "
        "invisibly during screen-shares/recordings (interviews, exams, "
        "meetings) to avoid detection by proctoring or screen-capture "
        "software. Its presence on a personal workstation is unusual "
        "software worth noting; no malicious activity is implied, but it is "
        "the type of tool that can trip 'unauthorized software' or academic/ "
        "interview integrity policies."
    ),
    category="execution_evidence",
    evidence_anchor=EvidenceAnchor(
        source_id=src_pf.source_id,
        tool_execution_id="exec-pf-list",
        artifact_path="C:\\Windows\\Prefetch\\CLUELY.EXE-333AB11B.pf",
        log_entry="CLUELY.EXE-333AB11B.pf",
    ),
)

# --- F-009: Game-cheat-style toolkit prefetch alongside anti-cheat protected games ---
f9 = mgr.add_finding(
    summary=(
        "Prefetch evidence shows execution of GET-GRAPHICS-OFFSETS32.EXE, "
        "GET-GRAPHICS-OFFSETS64.EXE, STREEM.EXE, SWITCHBLADE_HOST.EXE, "
        "BTOOL.EXE, and PET.EXE, alongside RAINBOWSIX_BE.EXE (Rainbow Six "
        "Siege's BattlEye anti-cheat component, also seen executing in the "
        "BAM data) and GTA5_ENHANCED_BE.EXE (GTA5 Enhanced's BattlEye "
        "component). 'Get-Graphics-Offsets' style utilities are commonly "
        "associated with game-cheat/trainer toolkits that dump in-memory "
        "structure offsets for building ESP/overlay cheats, and are a "
        "recognized malware delivery vector (cheat loaders bundling "
        "infostealers). This combination of filenames is unusual software "
        "warranting follow-up — specifically identifying the on-disk paths "
        "and hashes of these binaries (not recoverable from filenames alone "
        "since Prefetch is MAM-compressed and no decompressor was available)."
    ),
    category="execution_evidence",
    evidence_anchor=EvidenceAnchor(
        source_id=src_pf.source_id,
        tool_execution_id="exec-pf-list",
        artifact_path="C:\\Windows\\Prefetch\\GET-GRAPHICS-OFFSETS64.EXE-2883828B.pf",
        log_entry=(
            "GET-GRAPHICS-OFFSETS32.EXE-D180B9CA.pf\n"
            "GET-GRAPHICS-OFFSETS64.EXE-2883828B.pf\n"
            "STREEM.EXE-2D6A09A2.pf\n"
            "SWITCHBLADE_HOST.EXE-3EB43185.pf\n"
            "BTOOL.EXE-51372FC5.pf\n"
            "PET.EXE-1AD9D175.pf\n"
            "RAINBOWSIX_BE.EXE-127869EE.pf\n"
            "GTA5_ENHANCED_BE.EXE-3E047DE7.pf"
        ),
    ),
    mitre_attack=["T1588.002"],
)
mgr.add_task(
    description=(
        "Identify on-disk paths/hashes for GET-GRAPHICS-OFFSETS32/64.EXE, "
        "STREEM.EXE, SWITCHBLADE_HOST.EXE, BTOOL.EXE, and PET.EXE "
        "(e.g. via filesystem triage or a Prefetch/MAM decompressor) to "
        "determine whether these are game-cheat utilities or something else."
    ),
    triggered_by=f9.finding_id,
    priority="MEDIUM",
)

# --- F-010: Event log review - nothing anomalous found ---
f10 = mgr.add_finding(
    summary=(
        "Reviewed System.evtx and Security.evtx via 'strings -el' (no "
        "EvtxECmd available, so structured BinXML records could not be "
        "parsed; only embedded UTF-16LE string fragments were searched). "
        "No remote/external IP addresses were found in Security.evtx (only "
        "127.0.0.1, 27 occurrences); no command-line content from process- "
        "creation auditing was recoverable (CommandLine field names appear "
        "in event templates but populated values were not extracted as "
        "plain strings); no PowerShell encoded-command, IEX, or suspicious "
        "rundll32/cmd patterns were found; no account names beyond the "
        "known local accounts (Aditya, Administrator, Guest, DefaultAccount, "
        "WDAGUtilityAccount, Splunkd) appeared. This negative result is noted "
        "per analysis rules; a structured EVTX parse (EvtxECmd/python-evtx) "
        "would be needed for a definitive review of logon/process-creation "
        "events."
    ),
    category="event_log",
    status=FindingStatus.INFERRED,
    evidence_anchor=EvidenceAnchor(
        source_id=src_evtx_sec.source_id,
        tool_execution_id="exec-evtx-security",
        log_entry="127.0.0.1 (27 occurrences); no other IPv4 addresses found in Security.evtx string extraction",
    ),
)
mgr.set_reasoning_chain(
    f10.finding_id,
    premises=[
        "strings -el extraction of Security.evtx yields only loopback (127.0.0.1) IP literals.",
        "strings -el extraction of System.evtx/Security.evtx shows no encoded PowerShell, IEX, or suspicious rundll32/cmd command fragments.",
        "Only previously-known local account names appear in extracted strings.",
    ],
    logic=(
        "Absence of remote-IP logons, suspicious command-line fragments, or "
        "unknown account names in the extractable event log strings "
        "corroborates the host-profile picture from the registry analysis "
        "(personal workstation, no evidence of remote compromise), though "
        "this is a weak negative result given strings-based extraction "
        "cannot read structured/binary event fields."
    ),
    corroboration_type=CorroborationType.SINGLE_SOURCE_NARRATED,
)

mgr.save(graph_path)

# Run validators on the new findings
pipeline = create_default_pipeline()
context = {
    "evidence_sources": [s.to_dict() for s in mgr.graph.evidence_sources],
    "raw_outputs": {
        "exec-rr-system": open("/tmp/rr_system.txt", encoding="utf-8", errors="replace").read(),
        "exec-rr-software": open("/tmp/rr_software.txt", encoding="utf-8", errors="replace").read(),
        "exec-rr-sam": open("/tmp/rr_sam.txt", encoding="utf-8", errors="replace").read(),
        "exec-pf-list": open("/tmp/pf_names_full.txt", encoding="utf-8", errors="replace").read(),
        "exec-evtx-system": open("/tmp/sys_evtx_strings.txt", encoding="utf-8", errors="replace").read(),
        "exec-evtx-security": open("/tmp/sec_evtx_strings.txt", encoding="utf-8", errors="replace").read(),
    },
}

for finding in (f8, f9, f10):
    results = pipeline.validate_finding(finding, context)
    for r in results:
        mgr.add_validation_result(finding.finding_id, r)
        print(f"{finding.finding_id} :: {r.validator_name} -> {r.verdict.value}: {r.detail[:120]}")
    hard = [r for r in results if r.verdict == ValidatorVerdict.FAIL_HARD]
    if hard:
        mgr.eliminate_finding(finding.finding_id, reason=f"Validator: {hard[0].detail}", triggered_by=f"validator:{hard[0].validator_name}")
        print(f"ELIMINATED {finding.finding_id}")

mgr.save(graph_path)
print("done")
