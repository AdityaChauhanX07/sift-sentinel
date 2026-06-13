# SIFT Sentinel

**A grounded forensic reasoning engine for Protocol SIFT — deterministic hallucination catching for autonomous incident response.**

> Built for the [Find Evil! Hackathon](https://findevil.devpost.com/) — AI threats strike in minutes. Build the defender that responds in seconds.

## What SIFT Sentinel Does

SIFT Sentinel wraps the SANS SIFT Workstation's forensic tools in a typed MCP interface and records every finding in a structured evidence graph. Unlike standard agent approaches that add more LLM reasoning to catch errors, Sentinel reduces hallucination surface by using **deterministic code-level validators** — no LLM involved — to catch factual fabrications before they reach the final report.

Every finding in a Sentinel report is anchored to a specific artifact (file path, hash, offset, or log entry) that a human examiner can independently verify. Findings are classified by confidence: CONFIRMED (independently verified by 2+ artifact types), INFERRED (corroborating evidence with cited reasoning chain), or HYPOTHESIS (initial assessment pending verification). Findings that fail validation are visibly ELIMINATED with full reasoning — demonstrating self-correction, not hiding errors.

### Key Capabilities

- **Typed MCP Tool Interface** — Structured, type-safe wrappers for SIFT tools. The agent physically cannot run destructive commands because the MCP server doesn't expose them. Evidence is mounted read-only at the OS level.

- **Evidence Graph** — Central JSON data structure where every finding must have an evidence anchor. Findings are promoted or demoted through HYPOTHESIS → INFERRED → CONFIRMED lifecycle with full audit trail.

- **Five Deterministic Validators** — Code-level checks (zero LLM) that catch factual hallucinations:
  - Platform Consistency: Windows artifact on Linux image? Impossible.
  - Temporal Physics: Timestamp after evidence capture? Impossible.
  - Path Existence: Claimed file doesn't exist? Flagged (with forensic path variant resolution).
  - Hash Verification: File hash doesn't match? Fabricated.
  - Tool Output Fidelity: Agent claims tool found X, but X appears nowhere in the raw output? Fabricated.

- **Intra-Source Correlation** — Six cross-checks between independent artifact types within a single disk image (Prefetch ↔ AmCache, MFT ↔ Event Logs, Registry ↔ Filesystem, etc.) catch inconsistencies that are either forensically interesting or hallucinated.

- **Reasoning Chain Requirements** — Every inference must cite its premises and articulate the logic. Corroboration type (independent_sources / single_source_corroborated / single_source_narrated) is tagged so report readers can calibrate trust.

- **Benchmark Harness** — Quantitative comparison against Protocol SIFT baseline with mean ± standard deviation across multiple runs. Precision, grounding rate, and residual hallucination rate as headline metrics.

## Architecture

```
Evidence (read-only, OS-enforced)
│
▼
Custom MCP Server (typed tools, no shell access)
│
▼
Claude Code Agent (system prompt + self-review)
│
▼
Evidence Graph (findings enter → validators challenge → promote/demote/eliminate)
│
▼
Intra-Source Correlation (6 cross-checks between artifact types)
│
▼
Forensic Analysis Report (every claim traceable to a specific tool execution)
```

**Architectural guardrails** (enforced by code, not prompts):
- Read-only evidence mounting (OS-level)
- SHA-256 integrity manifest with post-execution verification
- Typed MCP tools with no destructive commands
- Deterministic validators (zero LLM involvement)
- Evidence-borne prompt injection defense (evidence parsed as data, never as instructions)

**Prompt-based guardrails** (enforced by agent instructions):
- Analysis workflow sequencing
- Reasoning chain requirements
- Self-review pass
- Competing hypothesis generation

This distinction is documented explicitly because it matters for trust.

## Quick Start

### Prerequisites

- Python 3.10+
- SANS SIFT Workstation ([install guide](https://github.com/sans-dfir/sift))
- Claude Code CLI (for agent-driven analysis)

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/sift-sentinel.git
cd sift-sentinel
./scripts/install.sh
```

Or manually:
```bash
pip install -e .
```

### Run an Analysis

```bash
# Basic analysis
sift-sentinel --evidence /path/to/evidence --output ./results

# With a specific case ID
sift-sentinel --evidence /path/to/evidence --output ./results --case-id CASE-2026-001

# Resume a previous analysis
sift-sentinel --resume ./results

# Regenerate report from existing evidence graph
sift-sentinel --report-only --output ./results
```

Or use the wrapper script:
```bash
./scripts/run_analysis.sh /path/to/evidence ./results CASE-2026-001
```

### Output Structure

```
results/
├── evidence_graph.json          # Complete evidence graph with all findings
├── evidence_manifest.json       # SHA-256 hashes of all evidence files
├── execution_log.json           # Full tool execution log
├── reports/
│   └── analysis_report.md       # Structured forensic report
├── snapshots/                   # Evidence graph at each analysis phase
├── raw/                         # Raw tool output files
└── mnt/                         # Evidence mount points
```

## Project Structure

```
sift-sentinel/
├── src/sift_sentinel/
│   ├── evidence_graph/          # Core data model and lifecycle management
│   │   ├── models.py            # 13 typed models (10 dataclasses + 3 enums: Finding, EvidenceAnchor, etc.)
│   │   └── graph.py             # CRUD operations, status promotion/demotion
│   ├── validators/              # Deterministic hallucination catchers (no LLM)
│   │   ├── base.py              # Abstract validator + pipeline orchestrator
│   │   ├── platform_consistency.py
│   │   ├── temporal_physics.py
│   │   ├── path_existence.py
│   │   ├── hash_verification.py
│   │   ├── tool_output_fidelity.py
│   │   └── factory.py           # Default pipeline with all 5 validators
│   ├── correlation/             # Cross-artifact contradiction detection
│   │   ├── checks.py            # 6 intra-source correlation checks
│   │   └── engine.py            # Orchestrator + graph integration
│   ├── mcp_server/              # Typed tool interface (no shell access)
│   │   ├── tools.py             # 7 SIFT tool wrappers
│   │   ├── response_envelope.py # Standardized tool response format
│   │   └── evidence_mount.py    # Read-only mounting + integrity verification
│   ├── agent/                   # Agent prompts and workflow
│   │   ├── system_prompt.md     # Core agent instructions
│   │   ├── self_review_prompt.md # Adversarial self-review checklist
│   │   └── workflow.py          # Analysis orchestrator + state management
│   ├── report/                  # Report generation
│   │   └── generator.py         # Evidence graph → Markdown report
│   ├── benchmark/               # Quantitative accuracy measurement
│   │   └── scorer.py            # Ground truth comparison + variance
│   └── cli.py                   # Command-line entry point
├── docs/                        # Submission documentation
├── scripts/
│   ├── install.sh               # One-command installer
│   └── run_analysis.sh          # Analysis wrapper script
└── logs/                        # Runtime logs (git-ignored contents)
```

## Design Philosophy

### The Precision-Recall Tradeoff

SIFT Sentinel deliberately trades recall for precision. It refuses to assert what it cannot ground in a specific artifact with a traceable tool execution. The Protocol SIFT baseline does the opposite — it confidently guesses, and some of those guesses are correct.

The result: Sentinel reports fewer findings than the baseline, but every finding is verifiable. In an incident response context where the report may reach legal counsel or a remediation team, that traceability is the difference between actionable and unreliable.

### What We Prove vs. What We Constrain

**Provably prevented** (architectural enforcement):
- Factual hallucinations (fabricated paths, hashes, timestamps) — via deterministic validators
- Evidence spoliation — via OS-level read-only mounts and typed MCP tools
- Evidence-borne prompt injection — via structured data parsing

**Structurally constrained** (not guaranteed):
- Reasoning hallucinations (false causal stories built on real facts) — via premise citation, corroboration typing, and self-review

This distinction matters. We state it because honest scoping is evidence of rigor, not a weakness.

## Judging Criteria Mapping

| Criterion | How SIFT Sentinel Addresses It |
|---|---|
| Autonomous Execution (tiebreaker) | Visible promote/demote cycle in evidence graph. Findings enter, get challenged by validators, change status with logged reasoning. |
| IR Accuracy | Factual hallucinations caught by code. Confirmed vs. inferred vs. hypothesis is the graph's native language. Quantitative benchmark with variance. |
| Breadth and Depth | Exhaustive intra-source correlation across 6 independent artifact types within a single disk image. Depth over breadth. |
| Constraint Implementation | 100% architectural for evidence integrity. Typed MCP tools, OS-level read-only mounts, deterministic validators. Tested for bypass. |
| Audit Trail | The evidence graph IS the audit trail. Every finding traces to a tool execution. Every status change is logged. |
| Usability and Documentation | One-command install. Single entry point. Structured output. This README. |

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

- [SANS SIFT Workstation](https://github.com/sans-dfir/sift) — 18 years of community-built forensic tools
- [Protocol SIFT](https://github.com/teamdfir/protocol-sift) — the MCP framework connecting AI agents to SIFT
- [Find Evil! Hackathon](https://findevil.devpost.com/) — organized by SANS Institute
