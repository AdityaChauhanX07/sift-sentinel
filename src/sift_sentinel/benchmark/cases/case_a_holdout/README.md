# Case A: Hackathon-Provided Holdout

**Source:** hackathon_provided  
**Status:** HOLDOUT — do NOT iterate the agent against this data during development.

## Purpose

This case uses sample evidence provided by the Find Evil! hackathon organizers.
The ground truth is derived from manual analysis or community-published findings,
NOT authored by the SIFT Sentinel team.

This is the most credible benchmark case because:
- We did not author the evidence
- We did not tune the agent against it
- Results are blind

## Setup

1. Download the sample case data from the Protocol SIFT Slack or hackathon resources
2. Place the evidence files in this directory
3. Create a `ground_truth.json` file based on manual analysis findings
4. Run the benchmark: the variance runner will score agent output against this ground truth

## Ground Truth Format

See `../case_b_malware/ground_truth.json` for the expected format.
The ground truth file should be loadable via `GroundTruth.from_dict(json.load(f))`.
