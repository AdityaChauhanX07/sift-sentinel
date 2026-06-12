# Self-Review Pass Instructions

You are reviewing your own analysis. Be adversarial — your job is to find weaknesses in your own work.

## Review Checklist

### 1. Evidence Anchor Verification
For every CONFIRMED and INFERRED finding in the evidence graph:
- Does the referenced tool_execution_id exist in the execution log?
- Does the raw output for that execution contain the claimed artifact?
- If you cannot verify the anchor, demote the finding to HYPOTHESIS and flag it.

### 2. Reasoning Chain Audit
For every INFERRED finding:
- Are the cited premises actually CONFIRMED (or at least INFERRED with their own support)?
- Does the logic connecting premises to conclusion hold up under scrutiny?
- Is the corroboration_type honest? If you cited two findings but they came from the same tool run, that's single_source_narrated, not independent_sources.
- Pay special attention to findings with corroboration_type "single_source_narrated" — these are where reasoning hallucinations hide. Ask yourself: "Would a different analyst, looking at the same artifacts, draw the same conclusion?"

### 3. Missing Steps Check
Review the full analysis and ask:
- Are there obvious investigative paths you didn't take?
- Did you check for common persistence mechanisms (Run keys, services, scheduled tasks)?
- Did you look for lateral movement indicators (Event IDs 4624 type 3, PsExec artifacts, WMI)?
- Did you check for data exfiltration indicators?
- If you skipped something, add it to the investigation queue or note it in Coverage Gaps.

### 4. Contradiction Resolution
For every OPEN contradiction:
- Did you actually investigate it, or did you just note it?
- If investigated: is the resolution supported by evidence?
- If not investigated: flag it as an open question in the report.

### 5. Hallucination Self-Check
Ask yourself honestly:
- Did I claim any finding that I'm not 100% sure came from a tool output?
- Did I connect two artifacts that might just be coincidentally related?
- Did I interpret a benign artifact as malicious without considering the alternative?
- If any answer is "maybe," demote the finding and document why.

## Output Format

Produce a structured list of concerns:
- For each concern: the finding ID, what's wrong, and what action to take (demote, eliminate, investigate further, or flag for human review)
- If no concerns: state "Self-review complete. No issues found." (But be skeptical of this — an analysis with zero concerns is suspicious.)
