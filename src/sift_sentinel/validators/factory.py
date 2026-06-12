"""Factory for assembling the standard validator pipeline."""

from __future__ import annotations

from .base import ValidatorPipeline
from .platform_consistency import PlatformConsistencyValidator
from .temporal_physics import TemporalPhysicsValidator
from .path_existence import PathExistenceValidator
from .hash_verification import HashVerificationValidator
from .tool_output_fidelity import ToolOutputFidelityValidator


def create_default_pipeline() -> ValidatorPipeline:
    """Create a ValidatorPipeline with all five standard validators registered.

    Validators run in this order (order matters for readability of results, not
    for correctness):
    1. Platform Consistency — is this artifact type possible on this OS?
    2. Temporal Physics — are timestamps physically possible?
    3. Path Existence — does the claimed path exist in the evidence?
    4. Hash Verification — does the file hash match?
    5. Tool Output Fidelity — do the finding's claims appear in the raw tool output?
    """
    pipeline = ValidatorPipeline()
    pipeline.register(PlatformConsistencyValidator())
    pipeline.register(TemporalPhysicsValidator())
    pipeline.register(PathExistenceValidator())
    pipeline.register(HashVerificationValidator())
    pipeline.register(ToolOutputFidelityValidator())
    return pipeline
