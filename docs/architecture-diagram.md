# SIFT Sentinel — Architecture Diagram

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              SIFT Sentinel                                      │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐     │
│  │                         AGENT LAYER                                    │     │
│  │                    (Prompt-Based Guardrails)                            │     │
│  │                                                                        │     │
│  │   ┌──────────────┐  ┌──────────────────┐  ┌───────────────────────┐    │     │
│  │   │ System Prompt │  │ Self-Review Pass │  │ Analysis Safeguards   │    │     │
│  │   │ (7 rules)     │  │ (5-point audit)  │  │ (caps, stuck detect)  │    │     │
│  │   └──────────────┘  └──────────────────┘  └───────────────────────┘    │     │
│  └─────────────────────────────┬──────────────────────────────────────────┘     │
│                                │                                                │
│                                ▼                                                │
│  ┌─────────────────────────────────────────────────────────────────────────┐     │
│  │                      EVIDENCE GRAPH                                    │     │
│  │                   (Central JSON Spine)                                  │     │
│  │                                                                        │     │
│  │   Findings ──── Status Lifecycle ──── Reasoning Chains                 │     │
│  │   (HYPOTHESIS → INFERRED → CONFIRMED / ELIMINATED)                     │     │
│  │                                                                        │     │
│  │   Every finding has:                                                   │     │
│  │   • Evidence anchor (artifact path, hash, offset, or log entry)        │     │
│  │   • Validation results (from 5 deterministic validators)               │     │
│  │   • Promotion history (every status change logged)                     │     │
│  │   • Reasoning chain (premises, logic, corroboration type)              │     │
│  │   • Contradiction links                                                │     │
│  └────────┬────────────────────────────────────┬──────────────────────────┘     │
│           │                                    │                                │
│           ▼                                    ▼                                │
│  ┌─────────────────────┐            ┌──────────────────────────┐                │
│  │  VALIDATOR PIPELINE  │            │  CORRELATION ENGINE      │                │
│  │  (Architectural)     │            │  (Architectural)         │                │
│  │  Zero LLM            │            │                          │                │
│  │                      │            │  Intra-Source (6 checks): │                │
│  │  1. Platform         │            │  • Prefetch ↔ AmCache    │                │
│  │     Consistency      │            │  • MFT ↔ Prefetch paths  │                │
│  │  2. Temporal Physics │            │  • Registry ↔ Filesystem │                │
│  │  3. Path Existence   │            │  • MFT ↔ Event Log times │                │
│  │  4. Hash Verification│            │  • Prefetch ↔ Event count│                │
│  │  5. Tool Output      │            │  • AmCache ↔ File hashes │                │
│  │     Fidelity         │            │                          │                │
│  │                      │            │  Cross-Source (3 checks): │                │
│  │  HARD → ELIMINATE    │            │  • Process existence     │                │
│  │  SOFT → FLAG         │            │  • Network activity      │                │
│  │  N/A  → SKIP         │            │  • Timestamp consistency │                │
│  └──────────┬───────────┘            └────────────┬─────────────┘                │
│             │                                     │                              │
│             └──────────────┬──────────────────────┘                              │
│                            │                                                     │
│                            ▼                                                     │
│  ┌─────────────────────────────────────────────────────────────────────────┐     │
│  │                    CUSTOM MCP SERVER                                    │     │
│  │                  (Architectural Guardrails)                              │     │
│  │                                                                        │     │
│  │   12 Typed Tool Functions          Response Envelope                   │     │
│  │   ┌─────────────────────┐         ┌──────────────────────┐             │     │
│  │   │ extract_mft_timeline│         │ execution_id          │             │     │
│  │   │ parse_prefetch      │         │ raw_output_hash       │             │     │
│  │   │ analyze_registry    │         │ parsed_output (JSON)  │             │     │
│  │   │ parse_event_logs    │         │ normalized_fields     │             │     │
│  │   │ extract_amcache     │         │ integrity_check       │             │     │
│  │   │ compute_file_hash   │   ───▶  │   pre_hash            │             │     │
│  │   │ extract_strings     │         │   post_hash           │             │     │
│  │   │ memory_processes    │         │   match: true/false   │             │     │
│  │   │ memory_network      │         └──────────────────────┘             │     │
│  │   │ memory_malfind      │                                              │     │
│  │   │ parse_lnk_files     │         Injection Defense                    │     │
│  │   │ analyze_usn_journal │         ┌──────────────────────┐             │     │
│  │   └─────────────────────┘         │ Evidence parsed as    │             │     │
│  │                                   │ structured data fields│             │     │
│  │   NO shell access                 │ — never as prompt text│             │     │
│  │   NO file write/delete            └──────────────────────┘             │     │
│  │   NO arbitrary commands                                                │     │
│  │   ALL params typed + validated                                         │     │
│  └─────────────────────────────────────┬──────────────────────────────────┘     │
│                                        │                                        │
│                                        ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────────┐     │
│  │                   READ-ONLY EVIDENCE LAYER                             │     │
│  │                   (Architectural Guardrail)                             │     │
│  │                                                                        │     │
│  │   OS-level mount -o ro,loop    SHA-256 Manifest                        │     │
│  │   Non-root MCP server user     Pre/post execution verification         │     │
│  │                                                                        │     │
│  │   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐              │     │
│  │   │ Disk     │  │ Memory   │  │ Log      │  │ Network  │              │     │
│  │   │ Images   │  │ Captures │  │ Files    │  │ Captures │              │     │
│  │   │ (.E01,   │  │ (.mem,   │  │ (.evtx,  │  │ (.pcap,  │              │     │
│  │   │  .raw)   │  │  .dmp)   │  │  .log)   │  │  .pcapng)│              │     │
│  │   └──────────┘  └──────────┘  └──────────┘  └──────────┘              │     │
│  └─────────────────────────────────────────────────────────────────────────┘     │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐     │
│  │                         OUTPUT                                         │     │
│  │                                                                        │     │
│  │   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                 │     │
│  │   │ Forensic     │  │ Evidence     │  │ Execution    │                 │     │
│  │   │ Report (.md) │  │ Graph (.json)│  │ Log (.json)  │                 │     │
│  │   │ 10 sections  │  │ Full audit   │  │ Every tool   │                 │     │
│  │   │ with corr.   │  │ trail with   │  │ call with    │                 │     │
│  │   │ type emojis  │  │ promotion    │  │ raw output   │                 │     │
│  │   │ 🟢🟡🟠       │  │ history      │  │ preserved    │                 │     │
│  │   └──────────────┘  └──────────────┘  └──────────────┘                 │     │
│  └─────────────────────────────────────────────────────────────────────────┘     │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Trust Boundary Legend

```
┌──────────────────────────────────────────────────────────────┐
│  ARCHITECTURAL GUARDRAILS (enforced by code)                 │
│  ═══════════════════════════════════════                     │
│  • Read-only evidence mount (OS-level)                       │
│  • Typed MCP tools (no shell, no destructive ops)            │
│  • SHA-256 integrity manifest with post-exec verification    │
│  • Deterministic validators (zero LLM, code-only)            │
│  • Structured data parsing (injection defense)               │
│  • Evidence anchor requirement (EvidenceAnchor.post_init)│
│                                                              │
│  Cannot be bypassed by prompt injection, adversarial input,  │
│  or model non-compliance.                                    │
├──────────────────────────────────────────────────────────────┤
│  PROMPT-BASED GUARDRAILS (enforced by agent instructions)    │
│  ─────────────────────────────────────                       │
│  • System prompt (7 rules, 8-step workflow)                  │
│  • Self-review pass (5-point checklist)                      │
│  • Reasoning chain requirements                              │
│  • Competing hypothesis generation                           │
│  • Corroboration type tagging                                │
│                                                              │
│  May be bypassed if model deviates from instructions.        │
│  Backed by architectural catch layers (validators).          │
└──────────────────────────────────────────────────────────────┘
```

## Data Flow: Finding Lifecycle

```
Agent discovers artifact
│
▼
Finding enters Evidence Graph as HYPOTHESIS
(evidence anchor required — EvidenceAnchor.post_init)
│
▼
Validator Pipeline runs (5 checks, post-entry, visible)
│
├── HARD failure ──▶ ELIMINATED (logged with reasoning)
│                    ↑ This IS the visible self-correction
│
├── SOFT failure ──▶ Stay HYPOTHESIS + FLAG
│                    (agent must address flag before promotion)
│
└── All PASS ──▶ Eligible for promotion
│
▼
Corroborating evidence found?
│
├── YES ──▶ Promote to INFERRED
│           (requires reasoning chain + corroboration type)
│           │
│           ├── 🟢 independent_sources (2+ artifact types)
│           ├── 🟡 single_source_corroborated
│           └── 🟠 single_source_narrated (flagged in report)
│                   │
│                   ▼
│           Independent verification?
│                   │
│                   ├── YES ──▶ CONFIRMED
│                   └── NO  ──▶ Stay INFERRED
│
└── NO ──▶ Stay HYPOTHESIS
(record "investigated, not confirmed")
```
