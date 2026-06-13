# Case D: Anti-Forensic Activity (Stretch Goal)

**Source:** self_authored  
**Status:** Stretch goal — build if time permits.

## What This Tests

This case contains evidence of anti-forensic techniques:
- Timestomped files ($STANDARD_INFORMATION timestamps modified, $FILE_NAME timestamps preserved)
- Deleted executables (recoverable via MFT $FILE_NAME entries)
- Cleared event logs (gaps in Event ID sequences)
- Modified registry entries

## Expected Behavior

1. The agent should detect timestamp inconsistencies between $SI and $FN timestamps
2. The agent should find deleted file records in MFT even when files are absent from the filesystem
3. The agent should notice gaps in event log sequences suggesting clearance
4. The intra-source correlation checks should flag these inconsistencies automatically

## Setup

1. Create a test disk image with planted anti-forensic artifacts
2. Document ground truth: what was modified, what the original values were
3. Create a `ground_truth.json` with expected findings

## Why This Is a Stretch Goal

Anti-forensic detection requires the deepest level of artifact analysis. The agent
must understand not just what artifacts say, but what they SHOULD say — and notice
when reality doesn't match expectations. This is the hardest test of analytical depth.
