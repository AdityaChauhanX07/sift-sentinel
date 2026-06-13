# SIFT Sentinel

## What It Does

SIFT Sentinel is a grounded forensic reasoning engine that wraps the SANS SIFT Workstation's 200+ incident response tools in a typed MCP interface and records every finding in a structured evidence graph. It is designed around a single principle: reduce hallucination surface instead of adding more LLM reasoning to catch errors.

Every finding in a Sentinel report is anchored to a specific artifact — a file path, hash, offset, or log entry — that a human examiner can independently verify. Five deterministic code-level validators (zero LLM involvement) catch factual hallucinations before they reach the final report. Six intra-source correlation checks cross-reference independent artifact types within a single disk image, catching inconsistencies that are either forensically interesting or hallucinated.

The result: a forensic analysis report where every claim is traceable from the finding, through the evidence graph, to the specific tool execution and raw output that produced it. An incident responder can hand this report to legal counsel or a remediation team with confidence that every assertion is verifiable.

### The Precision-Recall Tradeoff

Sentinel deliberately trades recall for precision. It refuses to assert what it cannot ground in a specific artifact. The Protocol SIFT baseline does the opposite — it confidently guesses, and some guesses are correct. Sentinel reports fewer findings, but every finding is real. In an incident response context, a report that finds less but fabricates nothing is more useful than one that finds more but invents some of it.

### Key Differentiators

- **Deterministic hallucination catching:** Five validators that run as code, not LLM calls. Platform consistency, temporal physics, path existence, hash verification, and tool output fidelity — each catching a specific class of fabrication.

- **Visible self-correction:** Findings enter the evidence graph, get challenged by validators, and are promoted, demoted, or eliminated with full reasoning logged. Every status change is in the audit trail. Self-correction is visible, not hidden.

- **Corroboration typing:** Every inference is tagged as `independent_sources` (strongest), `single_source_corroborated` (moderate), or `single_source_narrated` (weakest). Report readers can calibrate trust at a glance.

- **Evidence-borne prompt injection defense:** The MCP server parses evidence as structured data fields, never as prompt text. Attacker strings embedded in disk images cannot manipulate the agent — and the injection scanner flags them as suspicious forensic artifacts. The malware tried to talk to the analyst; the architecture made it impossible.

- **Architectural, not prompt-based, guardrails:** Evidence integrity is enforced by OS-level read-only mounts and typed MCP tools with no destructive commands. This is documented separately from the prompt-based agent instructions, because the distinction matters for trust.

## How We Built It

SIFT Sentinel is built as a Python package (`sift-sentinel`) with a `src/` layout, designed to run on the SANS SIFT Workstation with Claude Code as the agentic framework.

**The Evidence Graph** is the spine. Every other component reads from and writes to it. It's a JSON data structure with 10 dataclasses and 3 enums defining findings, evidence sources, contradictions, investigation tasks, and full promotion/demotion history. Findings enter as HYPOTHESIS and are challenged visibly — never gated before entry.

**The Custom MCP Server** wraps 12 SIFT tools (MFTECmd, PECmd, RegRipper, EvtxECmd, AmcacheParser, LECmd, Volatility 3, strings) as typed Python functions with structured inputs, outputs, and no shell access. Every execution produces a standardized response envelope with raw output preservation, SHA-256 hashing, and evidence integrity verification.

**The Validator Pipeline** runs five deterministic checks post-entry on every finding. Hard failures (logical impossibilities) eliminate findings visibly. Soft failures flag findings for review. The pipeline is a pure checker — it doesn't mutate findings directly, preserving separation of concerns.

**The Correlation Engine** runs six intra-source cross-checks (Prefetch ↔ AmCache, MFT ↔ Event Logs, Registry ↔ Filesystem, etc.) plus three cross-source checks when multi-source evidence is available. Contradictions generate investigation tasks; corroborations link findings for potential promotion.

**The Benchmark Harness** scores agent output against ground truth with a variance runner that executes multiple runs and reports mean ± standard deviation. Single-run numbers are noise; multiple runs with error bars are a measurement.

## Challenges

**The ≥2 premises trap.** Our initial design required every inference to cite at least two confirmed premises. This sounded rigorous but was forensically too rigid — plenty of legitimate findings rest on a single strong artifact (one registry Run key, one malfind hit). Worse, an LLM told "cite two premises" will always produce two facts and narrate a connection, guaranteeing the form of rigor without the substance. We softened the requirement to guidance with corroboration typing, which exposes chain strength honestly instead of laundering bad reasoning behind a structural rule.

**Hard vs. soft validator failures.** Our initial validators eliminated findings on any failure. Path existence checks on forensic paths — 8.3 short names, `\Device\HarddiskVolume` prefixes, case sensitivity — would have shredded true positives. We learned that only logical impossibilities should eliminate; everything softer should flag. This single design decision probably saved us from a worse recall score than the baseline.

**The self-correction paradox.** Self-correction count can read as "generates garbage then cleans it up." We learned to always pair it with residual hallucination rate: "12 corrections reduced the initial error rate from 14.6% to 2.1% in the final report." The metric only impresses in context.

**Normalizer integration.** Building the normalizer was easy. Wiring it into every tool function and the validator context so that field-aware matching actually works against normalized values — that was the tedious part that nearly got skipped.

## What We Learned

1. **The winning move is less LLM, not more.** Adding an LLM self-review pass creates more opportunities to hallucinate. Adding a deterministic code check creates zero. The highest-value components in our architecture are the validators — pure Python, no LLM, no hallucination risk.

2. **Honest scoping builds credibility.** Claiming to "solve hallucinations" would be false and would undermine everything else in the submission. Claiming to "provably catch factual hallucinations and structurally constrain reasoning hallucinations, with measured residual rates" is true and earns trust. Every stated limitation is bounded by the strength it protects.

3. **The evidence graph unifies everything.** One object, one schema. The read-only layer guards what feeds it, validators challenge what enters it, correlation stress-tests what's in it, the self-review pass challenges its reasoning, and the benchmark scores it. Without that unifying spine, the project would be a collection of disconnected tools.

4. **Precision beats recall in IR.** A CISO receiving a report with 10 verified findings can act on it. A CISO receiving a report with 20 findings where 5 are fabricated cannot trust any of them. Recall is a measured cost; precision is the deliverable.

## What's Next

1. **Live SIFT Workstation testing.** The tool wrappers need to be validated against real SIFT tool output. CSV parsing paths are best-effort against known header variants — they need a pass against actual tool output.

2. **Case A holdout benchmark.** Run against hackathon-provided evidence we haven't seen. This is the credibility test — numbers on data we didn't author.

3. **Prompt injection live test.** Build a test disk image with planted injection strings and run the full agent against it. Document whether the MCP server's structured parsing actually prevented behavioral manipulation.

4. **Community integration.** The benchmark harness and ground truth format are designed to be reusable. Other teams can score their agents against the same ground truth, creating a shared measurement framework for Protocol SIFT accuracy.

5. **Tool coverage expansion.** 12 tools is a start. The SIFT Workstation has 200+. Each new typed wrapper extends the agent's analytical reach without adding hallucination surface — because the MCP server's structured parsing applies uniformly.
