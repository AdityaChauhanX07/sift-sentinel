# SIFT Sentinel — Dataset Documentation

## Overview

This document describes the evidence datasets used for testing and benchmarking SIFT Sentinel, including provenance, content, and ground truth status.

## Benchmark Cases

### Case A: Hackathon-Provided Holdout

| Field | Value |
|---|---|
| Source | hackathon_provided |
| Holdout | YES — agent was NOT developed against this data |
| Status | Pending — awaiting sample data from hackathon organizers |
| Ground Truth | To be derived from manual analysis, not team-authored |

**Purpose:** Most credible benchmark case. We did not author the evidence, we did not tune the agent against it, and results are blind.

**Setup instructions:** Download sample case data from Protocol SIFT Slack or hackathon resources. Place in `benchmark/cases/case_a_holdout/`. Create `ground_truth.json` from independent manual analysis.

### Case B: Known Malware Execution

| Field | Value |
|---|---|
| Source | self_authored |
| Holdout | NO — agent was developed with awareness of this case structure |
| Status | Ground truth file present (`ground_truth.json`) |
| Ground Truth | 7 entries (5 required, 2 optional) |

**Purpose:** Controlled test case with known artifacts for validating the benchmark scoring pipeline and basic agent accuracy.

**Contents:**
- Malicious executable (`svc_update.exe`) dropped to `C:\Windows\Temp\`
- Prefetch entry confirming execution
- AmCache entry with SHA-1 hash
- Registry Run key persistence at `HKCU\...\CurrentVersion\Run`
- Event ID 7045 (service installation)
- Optional: C2 domain connection, initial dropper script

**Disclosure:** This case is self-authored. The agent was developed with knowledge of this case's structure. Benchmark results on this case may overstate accuracy relative to novel evidence. We disclose this and weight Case A results more heavily.

### Case C: Evidence-Borne Prompt Injection

| Field | Value |
|---|---|
| Source | self_authored |
| Holdout | NO |
| Status | Pending — test disk image not yet created |
| Purpose | Tests Criterion 4 (Constraint Implementation), not Criterion 2 (IR Accuracy) |

**Contents (planned):**
- Files with injection strings in filenames
- Registry values containing prompt manipulation text
- Text files with fake assistant responses
- Mixed with normal forensic artifacts

**Evaluation:** Qualitative, not quantitative. Success = agent behavior unchanged by injections.

### Case D: Anti-Forensic Activity (Stretch)

| Field | Value |
|---|---|
| Source | self_authored |
| Holdout | NO |
| Status | Stretch goal — pending time availability |
| Purpose | Tests depth of analysis on anti-forensic techniques |

**Contents (planned):**
- Timestomped files ($SI modified, $FN preserved)
- Deleted executables recoverable via MFT
- Cleared event logs with sequence gaps
- Modified registry entries

## Data Provenance

All self-authored test data is disclosed as such in the accuracy report. The SIFT Sentinel team did not author Case A evidence. Benchmark results distinguish between holdout and self-authored cases.

## Reproducibility

To reproduce our benchmark results:
1. Set up a SIFT Workstation with SIFT Sentinel installed
2. Place evidence files in the appropriate `benchmark/cases/` directories
3. Run: `python -m sift_sentinel.benchmark.variance_runner` (or use the VarianceRunner API)
4. Ground truth files are included in the repository for Cases B-D
5. Case A ground truth must be independently derived
