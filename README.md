# SIFT Sentinel

A grounded forensic reasoning engine for Protocol SIFT. Deterministic hallucination catching for autonomous incident response.

Built for the [Find Evil! Hackathon](https://findevil.devpost.com/).

**[Analysis Report](example-output/reports/analysis_report.md)** | **[Evidence Graph](example-output/evidence_graph.json)**

## The Problem

AI agents hallucinate. In forensic incident response, a hallucinated finding - a fabricated file path, a made-up registry key, a timestamp that never existed - isn't just wrong. It's dangerous. It sends responders chasing ghosts while the real threat moves.

Protocol SIFT connects AI agents to the SANS SIFT Workstation's 200+ forensic tools through MCP. It works. It also hallucinates more than anyone's comfortable with.

Most teams try to fix this by adding more LLM reasoning - self-reflection, chain-of-thought, multi-agent debate. That's adding more surface area for hallucination, not less.

We went the other direction.

## What Sentinel Does

Sentinel catches hallucinations with **code, not more AI**. Five deterministic validators run against every finding the agent produces - zero LLM involvement. They check things a computer can verify without guessing:

- **Platform Consistency** - Did the agent claim a Windows registry key on a Linux image? That's impossible. Eliminated.
- **Temporal Physics** - Is the timestamp after the evidence was captured? That's physically impossible. Eliminated.
- **Path Existence** - Does the claimed file path actually exist? If not, flagged for review (forensic paths are messy, so this one never eliminates - just flags).
- **Hash Verification** - The agent said the file has hash X. We independently computed it. It's actually Y. The agent lied. Eliminated.
- **Tool Output Fidelity** - The agent claims a tool found something. We check the raw tool output. The thing isn't there. Anywhere. In any form. Eliminated.

Everything else - the evidence graph, the correlation engine, the report generator - is built to make these validators maximally effective.

## How It Actually Works

The agent analyzes evidence and produces findings. Every finding must have an **evidence anchor** - a specific file path, registry key, log entry, or hash that a human can independently verify. No anchor, no finding. The code enforces this.

Findings enter the evidence graph as HYPOTHESIS. Then the validators run - visibly, with results logged on every finding. Hard failures (logical impossibilities) eliminate the finding. Soft failures flag it. Everything is in the audit trail.

After validation, the correlation engine runs six cross-checks between independent artifact types. Does the Prefetch agree with AmCache about what executed? Does the registry Run key point to a file that actually exists? Do event log timestamps match MFT timestamps? Disagreements are either forensically interesting or caught hallucinations.

The end result is a report where every claim traces back to a specific tool execution and raw output. A responder can hand it to legal counsel knowing nothing in it was made up.

### The Self-Correction That Actually Happened

In our test run, the agent produced finding F-001 claiming a user account had "Password not required" set, citing registry path `SAM\SAM\Domains\Account\Users\000003E9`. The Tool Output Fidelity validator checked the raw RegRipper output. That path appeared nowhere in it. The validator returned FAIL_HARD - categorical absence - and the finding was eliminated.

The agent then re-recorded the same observation as F-007 with a corrected evidence anchor pointing to the actual RegRipper output text. The corrected finding passed all validators.

That's not a demo scenario. That's what happened when we ran it. F-001 is still in the evidence graph, marked ELIMINATED, with the full reasoning for why. The eliminated finding section of the report exists specifically to show judges (and practitioners) that the system catches its own mistakes rather than hiding them.

## The Precision-Recall Tradeoff

Sentinel finds less than the baseline. That's the design, not a bug.

It refuses to assert what it can't ground in a specific artifact. The Protocol SIFT baseline guesses confidently, and some of those guesses are correct. Sentinel won't guess. The result: fewer findings, but every finding is real.

In incident response, a report with 10 verified findings is actionable. A report with 20 findings where 5 are fabricated is useless - you can't trust any of them.

We report recall as a measured cost, not something we hide. Precision, grounding rate, and residual hallucination rate are our headline metrics.

## Quick Start

### What You Need

- Python 3.10+
- SIFT Workstation tools (RegRipper, Sleuth Kit, Volatility 3) - either via the [SIFT Workstation](https://github.com/sans-dfir/sift) or installed individually
- Claude Code CLI for agent-driven analysis

### Install

```bash
git clone https://github.com/AdityaChauhanX07/sift-sentinel.git
cd sift-sentinel
./scripts/install.sh
```

Or just:
```bash
pip install -e .
```

### Run

```bash
# Analyze evidence
sift-sentinel --evidence /path/to/evidence --output ./results --case-id CASE-001

# Resume a previous analysis
sift-sentinel --resume ./results

# Regenerate report from existing graph
sift-sentinel --report-only --output ./results
```

Then use Claude Code to drive the actual forensic analysis:

```bash
cd sift-sentinel
claude
> Analyze the evidence at /path/to/evidence following the CLAUDE.md instructions.
```

### What You Get

```
results/
├── evidence_graph.json        # Every finding with anchors, validation, promotion history
├── evidence_manifest.json     # SHA-256 hashes of all evidence files
├── execution_log.json         # Every tool call, timestamped
├── reports/
│   └── analysis_report.md     # 10-section forensic report
├── snapshots/                 # Graph state at each analysis phase
└── raw/                       # Raw tool output files
```

## Architecture

```
Evidence (read-only, OS-enforced)
    |
    v
Custom MCP Server (12 typed tools, no shell access)
    |
    v
Claude Code Agent (system prompt + self-review)
    |
    v
Evidence Graph (findings enter -> validators challenge -> promote/demote/eliminate)
    |
    v
Intra-Source Correlation (6 cross-checks between artifact types)
    |
    v
Forensic Analysis Report (every claim traceable to a tool execution)
```

### What's Architectural vs. What's Prompt-Based

This distinction matters. We document it because it affects how much you should trust each guardrail.

**Architectural (enforced by code - can't be bypassed by the LLM):**
- Read-only evidence mounting at the OS level
- SHA-256 integrity manifest verified after every tool execution
- Typed MCP tools with no destructive commands (no shell access, no file write/delete)
- Five deterministic validators (zero LLM involvement)
- Evidence-borne prompt injection defense (evidence parsed as structured data, never as prompt text)

**Prompt-based (enforced by agent instructions - can be bypassed if the model deviates):**
- Analysis workflow sequencing
- Reasoning chain and premise citation requirements
- Self-review pass
- Competing hypothesis generation

When prompt-based guardrails fail, the architectural validators catch the resulting errors. That's the safety net.

## What We Built

```
src/sift_sentinel/
├── evidence_graph/        # Data model + lifecycle (13 typed models, CRUD, persistence)
├── validators/            # 5 deterministic validators + pipeline + factory
├── correlation/           # 6 intra-source + 3 cross-source checks + engine
├── mcp_server/            # 12 typed tool wrappers, response envelopes, evidence mounting,
│                          # normalizer, injection defense
├── agent/                 # System prompt, self-review prompt, workflow orchestrator,
│                          # analysis safeguards
├── report/                # 10-section report generator
├── benchmark/             # Scorer, variance runner, ground truth, comparison
└── cli.py                 # Three modes: new analysis, resume, report-only
```

Plus: CLAUDE.md (agent instructions), install/run scripts, docs (6 submission documents), example output with real analysis results, and the website.

## What We Prove vs. What We Constrain

**Provably prevented:**
- Factual hallucinations (fabricated paths, hashes, timestamps) - deterministic validators
- Evidence spoliation - OS-level read-only mounts, typed MCP tools
- Evidence-borne prompt injection - structured data parsing

**Structurally constrained (not guaranteed):**
- Reasoning hallucinations (false causal stories on real facts) - premise citation, corroboration typing, self-review

We state this distinction because honest scoping is evidence of rigor. Claiming to "solve hallucinations" would be false. Claiming to provably catch factual hallucinations and structurally constrain reasoning hallucinations, with measured residual rates, is true.

## Judging Criteria

| Criterion | How We Address It |
|---|---|
| Autonomous Execution (tiebreaker) | Findings enter the graph, get challenged by validators, change status with logged reasoning. Self-correction is visible, not hidden. |
| IR Accuracy | Factual hallucinations caught by code. Confirmed/inferred/hypothesis is the graph's native language. |
| Breadth and Depth | Exhaustive intra-source correlation across 6 independent artifact types. Depth over breadth. |
| Constraint Implementation | 100% architectural for evidence integrity. Tested for bypass. Documented. |
| Audit Trail | The evidence graph IS the audit trail. Any finding -> tool execution -> raw output in one click. |
| Usability | One-command install. Single entry point. Working website. This README. |

## Team

Built for the Find Evil! Hackathon by the SIFT Sentinel team.

## License

MIT - see [LICENSE](LICENSE).

## Acknowledgments

- [SANS SIFT Workstation](https://github.com/sans-dfir/sift) - 18 years of community-built forensic tools
- [Protocol SIFT](https://github.com/teamdfir/protocol-sift) - MCP framework connecting AI agents to SIFT
- [Find Evil! Hackathon](https://findevil.devpost.com/) - organized by SANS Institute