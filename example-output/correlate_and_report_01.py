import sys
sys.path.insert(0, '/home/aditya/sift-sentinel/src')

from sift_sentinel.evidence_graph.graph import EvidenceGraphManager
from sift_sentinel.correlation.engine import CorrelationEngine
from sift_sentinel.report.generator import ReportGenerator
import datetime

graph_path = '/home/aditya/sentinel-output/evidence_graph.json'
mgr = EvidenceGraphManager.load(graph_path)

engine = CorrelationEngine(mgr)
result = engine.run_all_checks()
print(f"Contradictions: {result['contradictions_found']}, Corroborations: {result['corroborations_found']}")

mgr.graph.metadata.total_tool_executions = 3  # regripper runs against SYSTEM, SOFTWARE, SAM
mgr.graph.metadata.analysis_end = datetime.datetime.now(datetime.timezone.utc).isoformat()
mgr.save(graph_path)

reporter = ReportGenerator(mgr)
reporter.save_report('/home/aditya/sentinel-output/reports/analysis_report.md')
print("Report saved!")
print(mgr.get_summary())
