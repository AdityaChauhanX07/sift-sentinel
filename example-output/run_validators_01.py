import sys
sys.path.insert(0, '/home/aditya/sift-sentinel/src')

from sift_sentinel.validators import create_default_pipeline
from sift_sentinel.evidence_graph.models import ValidatorVerdict
from sift_sentinel.evidence_graph.graph import EvidenceGraphManager

graph_path = '/home/aditya/sentinel-output/evidence_graph.json'
mgr = EvidenceGraphManager.load(graph_path)

pipeline = create_default_pipeline()
context = {
    "evidence_sources": [s.to_dict() for s in mgr.graph.evidence_sources],
    "raw_outputs": {
        "exec-rr-system": open("/tmp/rr_system.txt", encoding="utf-8", errors="replace").read(),
        "exec-rr-software": open("/tmp/rr_software.txt", encoding="utf-8", errors="replace").read(),
        "exec-rr-sam": open("/tmp/rr_sam.txt", encoding="utf-8", errors="replace").read(),
    },
}

for finding in mgr.graph.findings:
    if finding.status.value != "ELIMINATED":
        results = pipeline.validate_finding(finding, context)
        for r in results:
            mgr.add_validation_result(finding.finding_id, r)
            print(f"{finding.finding_id} :: {r.validator_name} -> {r.verdict.value}: {r.detail[:120]}")

        hard = [r for r in results if r.verdict == ValidatorVerdict.FAIL_HARD]
        if hard:
            mgr.eliminate_finding(finding.finding_id,
                reason=f"Validator: {hard[0].detail}",
                triggered_by=f"validator:{hard[0].validator_name}")
            print(f"ELIMINATED {finding.finding_id}: {hard[0].detail}")

mgr.save(graph_path)
print("done")
