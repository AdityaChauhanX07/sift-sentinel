# SIFT Sentinel — Claim Scoping

## What We Prove vs. What We Constrain

This document explicitly distinguishes what SIFT Sentinel's architecture provably prevents from what it structurally constrains but cannot guarantee. This distinction matters for trust — overstating capability undermines credibility.

### Provably Prevented (Architectural Enforcement)

**Factual Hallucinations**
Fabricated file paths, hashes, timestamps, and tool outputs are caught by five deterministic code-level validators that run with zero LLM involvement:
- Platform Consistency: Windows artifacts on Linux images (and vice versa) are logically impossible and eliminated.
- Temporal Physics: Timestamps after evidence capture are physically impossible and eliminated.
- Hash Verification: File hashes independently computed and compared — mismatches mean fabrication.
- Tool Output Fidelity: Field-aware matching verifies the agent's claims appear in actual tool output. Categorical absence (claimed entity nowhere in raw or normalized output) triggers elimination.
- Path Existence: Forensic path variant resolution (8.3 names, volume prefixes, case sensitivity). Soft-only — flags but never eliminates, because forensic paths are messy.

These validators are code, not prompts. They cannot be bypassed by prompt injection, social engineering, or adversarial input.

**Evidence Spoliation**
Evidence is mounted read-only at the OS level (`mount -o ro,loop`). The MCP server exposes typed tool functions with no destructive commands — no `execute_shell_cmd`, no file write/delete/move, no arbitrary shell access. SHA-256 integrity manifest is computed before analysis and re-verified after each tool execution. The agent physically cannot modify evidence because the tools to do so don't exist.

**Evidence-Borne Prompt Injection**
The typed MCP server parses all evidence content as structured JSON data fields. Strings extracted from evidence appear inside JSON value fields (e.g., `{"strings": ["ignore all previous..."]}`) — they are data, not instructions. The `injection_defense.py` module additionally scans for known injection patterns and flags them as suspicious forensic artifacts — turning an attack on the analyst into a finding about the attacker.

### Structurally Constrained (Not Guaranteed)

**Reasoning Hallucinations**
False causal stories built on real facts — "this benign scheduled task is persistence" or "these three unrelated events form a lateral movement chain" — are the hardest hallucination type to catch. Our architecture constrains them through:
- Mandatory reasoning chains: every INFERRED finding must cite premises and articulate logic.
- Corroboration typing: `independent_sources` vs. `single_source_corroborated` vs. `single_source_narrated` makes chain strength immediately visible.
- Self-review pass: adversarial review specifically targets `single_source_narrated` chains.
- Intra-source correlation: six cross-checks between independent artifact types catch internally inconsistent narratives.

These measures reduce reasoning hallucinations and make them visible when they occur. They do not eliminate them. An LLM can construct a convincing but wrong causal story where the premises are real and the logic sounds plausible. We measure our residual reasoning hallucination rate and report it honestly.

### Known Limitations

1. **Validator false positives exist.** Path Existence and Hash Verification can flag legitimate findings due to forensic path complexity or deleted files. We track and report the validator false-positive rate separately from confirmed hallucinations.

2. **Recall is lower than the baseline.** Sentinel refuses to assert what it cannot ground. Some real findings that lack corroboration will remain at HYPOTHESIS status. This is a deliberate tradeoff documented in our benchmark results.

3. **Timestamp validation is opt-in per finding.** The temporal physics validator only checks timestamps explicitly provided in `context["finding_timestamps"]`. If the agent doesn't populate this field, the validator returns NOT_APPLICABLE — not a false PASS, but a coverage gap.

4. **Tool output fidelity has a substring matching bias.** Short filenames (e.g., `a.exe`) can match incidentally in large outputs. This bias is deliberate — it errs toward not flagging, which is the safe direction for a hallucination catcher, but it caps sensitivity.

5. **Cross-source correlation requires multi-source evidence.** If only a single disk image is available, cross-source checks don't fire. Intra-source correlation (6 checks within one disk image) partially compensates.

Each limitation above is bounded by a strength. We document them because honest self-measurement is the foundation of a trustworthy accuracy report.
