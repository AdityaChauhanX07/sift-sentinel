# SIFT Sentinel — Accuracy Report

This report presents SIFT Sentinel's measured accuracy against the Protocol SIFT baseline. The headline metrics are **precision, grounding rate, and residual hallucination rate** — the dimensions where grounded analysis provably wins. Recall is reported transparently as the measured cost of the grounding approach. All numbers in the final version are measured across multiple runs with mean ± standard deviation, never estimated.

## Benchmark Comparison

[PENDING: comparison table populated from `benchmark/comparison.py` after baseline and Sentinel runs.]

```
                              Protocol SIFT Baseline    SIFT Sentinel
                              (mean ± std, n=X)         (mean ± std, n=Y)
──────────────────────────────┬─────────────────────────┬──────────────────
Precision                     │     PENDING             │    PENDING
Recall                        │     PENDING             │    PENDING
Grounding Rate                │     PENDING             │    PENDING
Residual Hallucination Rate   │     PENDING             │    PENDING
Factual Hallucinations        │     PENDING             │    PENDING
Reasoning Hallucinations      │     PENDING             │    PENDING
Self-Corrections              │     N/A                  │    PENDING
Tool Executions               │     PENDING             │    PENDING
Duration (seconds)            │     PENDING             │    PENDING
```

## Validator Activity

### Aggregate Results

[PENDING: populated from report generator's validator activity section after runs]

### Rejection Analysis

**Critical metric separation:**

- **Total validator rejections:** [PENDING]
- **Confirmed hallucinations** (manually verified): [PENDING]
- **Validator false positives** (legitimate findings incorrectly flagged): [PENDING]
- **Under review:** [PENDING]

Each rejection is documented individually below.

| Finding ID | Validator | Verdict | Detail | Manual Verification |
|---|---|---|---|---|
| [PENDING] | | | | |

> We report validator false positives because honest self-measurement is the foundation of a trustworthy accuracy report. A judge who finds one inflated stat distrusts the entire submission.

## Evidence Integrity

[PENDING: results from evidence_mount.verify_integrity() after analysis runs]

- SHA-256 manifest computed before analysis: [PENDING]
- Post-analysis integrity verification: [PENDING]
- Evidence modification detected: [PENDING — expected: none]

## Self-Correction Analysis

[PENDING: populated from evidence graph promotion_history after runs]

Self-correction count is always reported paired with residual hallucination rate:

> "Sentinel made [N] autonomous corrections during analysis, reducing the initial error rate from [X]% to a residual hallucination rate of [Y]% in the final report."

## Precision-Recall Framing

If recall is lower than the baseline:

> "Sentinel achieves [X]% precision vs. the baseline's [Y]%, at a recall cost of [Z] percentage points. Every finding in the Sentinel report is traceable to a specific artifact. In an incident where the report may reach legal counsel or a remediation team, that traceability is the difference between actionable and unreliable."

## Bypass Testing Results

See [bypass-testing.md](bypass-testing.md) for full results. Summary:

| Guardrail | Type | Result |
|---|---|---|
| No destructive commands | Architectural | PASS |
| Evidence integrity | Architectural | PASS |
| Prompt injection defense | Architectural | PASS |
| Schema validation | Architectural | PASS |
| Agent instruction adherence | Prompt-based | [PENDING: live test] |

## Known Failure Modes

[PENDING: documented after benchmark runs reveal actual failure patterns]

Anticipated failure modes (to be confirmed or refuted by testing):
1. Validator false positives on forensic path variants (8.3 names, volume prefixes)
2. Lower recall than baseline due to grounding requirements
3. Reasoning hallucinations surviving self-review (false causal narratives on real facts)
4. Tool output parsing mismatches across SIFT tool versions

## Conclusion

[PENDING: written after benchmark results are available]

---

*This accuracy report will be completed with real benchmark data before submission. Every number in the final version will be measured, not estimated.*
