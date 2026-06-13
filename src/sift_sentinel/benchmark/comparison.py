"""Benchmark Comparison

Generates formatted comparison reports between Protocol SIFT baseline
and SIFT Sentinel runs, with proper framing of the precision-recall tradeoff.
"""

import os
from .scorer import BenchmarkScore, BenchmarkScorer


def generate_comparison_report(
    baseline_scores: list[BenchmarkScore],
    sentinel_scores: list[BenchmarkScore],
    case_name: str = "Unknown Case",
) -> str:
    """Generate a full markdown comparison report.

    This is the report that goes in accuracy-report.md and the demo video.
    It frames the precision-recall tradeoff correctly.
    """
    report_lines = [
        f"# Benchmark Comparison: {case_name}",
        "",
        "## Methodology",
        "",
        f"- Baseline runs: {len(baseline_scores)}",
        f"- Sentinel runs: {len(sentinel_scores)}",
        "- All runs against identical evidence with the same ground truth.",
        "- Metrics report mean ± standard deviation across runs.",
        "",
    ]

    # Generate the table using BenchmarkScorer's format method. The method does
    # not touch instance state, so an uninitialized instance is sufficient.
    scorer_instance = BenchmarkScorer.__new__(BenchmarkScorer)
    table = scorer_instance.format_comparison_table(baseline_scores, sentinel_scores)
    report_lines.append("## Results")
    report_lines.append("")
    report_lines.append("```")
    report_lines.append(table)
    report_lines.append("```")
    report_lines.append("")

    # Add the framing section
    report_lines.extend([
        "## Interpretation",
        "",
        "### Headline Metrics",
        "",
        "SIFT Sentinel's headline metrics are **precision**, **grounding rate**, and **residual hallucination rate** — the dimensions where grounded analysis provably wins.",
        "",
        "### Precision-Recall Tradeoff",
        "",
        "Sentinel deliberately trades recall for precision. It refuses to assert what it cannot ground in a specific artifact with a traceable tool execution.",
        "",
        "If recall is lower than the baseline, this is the design, not a failure. An incident response report where every claim is verifiable is more useful than one that finds more but fabricates some of it.",
        "",
        "### Self-Correction",
        "",
        "Self-correction count is reported paired with residual hallucination rate. A high self-correction count with a low residual rate means the system caught and fixed its own errors effectively.",
        "",
    ])

    return "\n".join(report_lines)


def save_comparison_report(
    baseline_scores: list[BenchmarkScore],
    sentinel_scores: list[BenchmarkScore],
    filepath: str,
    case_name: str = "Unknown Case",
) -> None:
    """Generate and save the comparison report."""
    report = generate_comparison_report(baseline_scores, sentinel_scores, case_name)
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report)
