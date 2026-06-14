import sys
sys.path.insert(0, '/home/aditya/sift-sentinel/src')

from sift_sentinel.evidence_graph.models import *
from sift_sentinel.evidence_graph.graph import EvidenceGraphManager
from sift_sentinel.validators import create_default_pipeline
from sift_sentinel.evidence_graph.models import ValidatorVerdict

graph_path = '/home/aditya/sentinel-output/evidence_graph.json'
mgr = EvidenceGraphManager.load(graph_path)

# F-001 was eliminated because its evidence_anchor.artifact_path
# (a constructed registry key path) does not appear verbatim in the
# RegRipper text output. Re-record the same substantive finding with
# an anchor that points only at content that is literally present in
# the tool output (the samparse log entry), avoiding the fabricated-path
# claim.
f1b = mgr.add_finding(
    summary=(
        "Local user account 'Aditya' (RID 1001, embedded RID 1001) is configured "
        "with 'Password not required' and carries a password hint reading 'Same "
        "as the main google account pass', indicating the local Windows password "
        "is reused for the user's Google account and that an empty/blank password "
        "would be accepted by Windows account policy for this account."
    ),
    category="account_anomaly",
    evidence_anchor=EvidenceAnchor(
        source_id="src-003",
        tool_execution_id="exec-rr-sam",
        log_entry=(
            "Username        : Aditya [1001]\n"
            "Password Hint   : Same as the main google account pass\n"
            "Embedded RID    : 1001\n"
            "  --> Password not required\n"
            "  --> Password does not expire"
        ),
    ),
)
mgr.add_flag(f1b.finding_id, "supersedes:F-001 (F-001 eliminated due to a fabricated artifact_path in its anchor; this finding restates the same substantive observation with a corrected anchor)")

mgr.save(graph_path)

# Re-run validators for the new finding
pipeline = create_default_pipeline()
context = {
    "evidence_sources": [s.to_dict() for s in mgr.graph.evidence_sources],
    "raw_outputs": {
        "exec-rr-system": open("/tmp/rr_system.txt", encoding="utf-8", errors="replace").read(),
        "exec-rr-software": open("/tmp/rr_software.txt", encoding="utf-8", errors="replace").read(),
        "exec-rr-sam": open("/tmp/rr_sam.txt", encoding="utf-8", errors="replace").read(),
    },
}

results = pipeline.validate_finding(f1b, context)
for r in results:
    mgr.add_validation_result(f1b.finding_id, r)
    print(f"{f1b.finding_id} :: {r.validator_name} -> {r.verdict.value}: {r.detail[:120]}")

hard = [r for r in results if r.verdict == ValidatorVerdict.FAIL_HARD]
if hard:
    mgr.eliminate_finding(f1b.finding_id, reason=f"Validator: {hard[0].detail}", triggered_by=f"validator:{hard[0].validator_name}")
    print(f"ELIMINATED {f1b.finding_id}")

mgr.save(graph_path)
print(f"Added {f1b.finding_id}")
