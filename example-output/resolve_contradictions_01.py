import sys
sys.path.insert(0, '/home/aditya/sift-sentinel/src')

from sift_sentinel.evidence_graph.graph import EvidenceGraphManager
import datetime

graph_path = '/home/aditya/sentinel-output/evidence_graph.json'
mgr = EvidenceGraphManager.load(graph_path)

resolution = (
    "Not a genuine contradiction: this evidence set contains only the SYSTEM, "
    "SOFTWARE, and SAM registry hives, EventLogs, and Prefetch directory — no "
    "AmCache.hve and no disk image/MFT/USN journal were collected, so "
    "cross-referencing against those artifact types is not possible here. "
    "The correlation engine's expectation reflects a data-availability gap, "
    "not evidence that the finding is fabricated; the Prefetch filename itself "
    "is the primary artifact and was verified present via directory listing."
)

for cid in ("C-001", "C-002", "C-003", "C-004"):
    mgr.resolve_contradiction(cid, resolution)

for fid in ("F-008", "F-009"):
    mgr.add_flag(fid, "amcache_mft_unavailable: AmCache/MFT/USN not collected for this case, cannot cross-validate")

# Mark the data-gap follow-up tasks as not applicable given no AmCache/MFT source exists
for tid, status in {
    "T-002": "BLOCKED", "T-003": "BLOCKED",
    "T-004": "BLOCKED", "T-005": "BLOCKED",
    "T-006": "BLOCKED", "T-007": "BLOCKED",
    "T-008": "BLOCKED", "T-009": "BLOCKED",
}.items():
    mgr.update_task_status(tid, status)

mgr.graph.metadata.analysis_end = datetime.datetime.now(datetime.timezone.utc).isoformat()
mgr.save(graph_path)
print("resolved")
