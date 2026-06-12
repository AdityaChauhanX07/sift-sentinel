"""Abstract base class for validators and the pipeline orchestrator.

Validators are deterministic, code-level checks — no LLM involvement. They run
*after* a finding has entered the graph and produce :class:`ValidationResult`
records. The pipeline is a pure checker: it never mutates findings, leaving the
decision of how to act on failures to the caller.
"""

from __future__ import annotations

import abc
import datetime

from ..evidence_graph.models import (
    Finding,
    FindingStatus,
    ValidationResult,
    ValidatorVerdict,
)


class BaseValidator(abc.ABC):
    """Base class for all deterministic validators.

    Validators use code-level checks only — no LLM involvement.
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """The validator's identifier, used as ValidationResult.validator_name."""
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def description(self) -> str:
        """One-line description of what this validator checks."""
        raise NotImplementedError

    @abc.abstractmethod
    def validate(self, finding: Finding, context: dict) -> ValidationResult:
        """Run the validation check against a finding.

        ``context`` carries external information the validator needs but that
        isn't on the Finding itself (e.g. ``evidence_sources``,
        ``mounted_evidence_path``, ``raw_outputs``, ``normalized_outputs``).

        Returns a :class:`ValidationResult` carrying this validator's name, a
        verdict, a detail string, and the current timestamp.
        """
        raise NotImplementedError

    def _make_result(self, verdict: ValidatorVerdict, detail: str) -> ValidationResult:
        """Build a ValidationResult stamped with this validator's name and now()."""
        return ValidationResult(
            validator_name=self.name,
            verdict=verdict,
            detail=detail,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )


class ValidatorPipeline:
    """Runs all registered validators against a finding after it enters the graph.

    Validators run post-entry. Results are returned to the caller for
    attachment. Hard failures inform status recommendations but do NOT
    directly modify the finding — the caller (graph manager or agent workflow)
    decides whether to act on them. This separation keeps the pipeline a pure
    checker, not a mutator.
    """

    def __init__(self):
        """Initialize an empty validator registry."""
        self._validators: list[BaseValidator] = []

    def register(self, validator: BaseValidator) -> None:
        """Register a validator; raises TypeError if not a BaseValidator instance."""
        if not isinstance(validator, BaseValidator):
            raise TypeError(
                f"Expected a BaseValidator instance, got {type(validator).__name__}"
            )
        self._validators.append(validator)

    def validate_finding(self, finding: Finding, context: dict) -> list[ValidationResult]:
        """Run every registered validator against the finding and collect results.

        Does NOT modify the finding — the caller is responsible for attaching
        the returned results.
        """
        return [validator.validate(finding, context) for validator in self._validators]

    def has_hard_failure(self, results: list[ValidationResult]) -> bool:
        """Return True if any result carries a FAIL_HARD verdict."""
        return any(r.verdict == ValidatorVerdict.FAIL_HARD for r in results)

    def get_hard_failures(self, results: list[ValidationResult]) -> list[ValidationResult]:
        """Return only the results with a FAIL_HARD verdict."""
        return [r for r in results if r.verdict == ValidatorVerdict.FAIL_HARD]

    def get_soft_failures(self, results: list[ValidationResult]) -> list[ValidationResult]:
        """Return only the results with a FAIL_SOFT verdict."""
        return [r for r in results if r.verdict == ValidatorVerdict.FAIL_SOFT]

    def summarize(self, results: list[ValidationResult]) -> dict:
        """Return a roll-up of verdict counts plus per-validator detail."""
        return {
            "total_validators_run": len(results),
            "passed": sum(1 for r in results if r.verdict == ValidatorVerdict.PASS),
            "hard_failures": sum(
                1 for r in results if r.verdict == ValidatorVerdict.FAIL_HARD
            ),
            "soft_failures": sum(
                1 for r in results if r.verdict == ValidatorVerdict.FAIL_SOFT
            ),
            "not_applicable": sum(
                1 for r in results if r.verdict == ValidatorVerdict.NOT_APPLICABLE
            ),
            "details": [
                {
                    "validator": r.validator_name,
                    "verdict": r.verdict.value,
                    "detail": r.detail,
                }
                for r in results
            ],
        }
