"""Analysis Safeguards

Iteration caps, stuck detection, and graceful degradation for the agent loop.
Prevents runaway execution and ensures partial results are always available.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class ExecutionRecord:
    """Tracks a single tool execution for stuck detection."""
    tool_name: str
    input_hash: str  # hash of the input parameters for dedup detection
    execution_id: str
    timestamp: str


class AnalysisSafeguards:
    """Enforces execution limits and detects stuck loops.

    The agent workflow calls check_* methods before each action.
    If any check fails, the agent should gracefully degrade:
    produce a partial report with a Coverage Gaps section.
    """

    def __init__(
        self,
        max_tool_executions: int = 200,
        max_investigation_iterations: int = 10,
        max_queue_depth: int = 50,
        warning_threshold: float = 0.8,
    ):
        self.max_tool_executions = max_tool_executions
        self.max_investigation_iterations = max_investigation_iterations
        self.max_queue_depth = max_queue_depth
        self.warning_threshold = warning_threshold

        self._tool_executions: int = 0
        self._investigation_iterations: int = 0
        self._execution_history: list[ExecutionRecord] = []
        self._stuck_detections: list[dict] = []
        self._warnings_issued: list[str] = []

    def record_execution(self, tool_name: str, input_params: dict, execution_id: str) -> None:
        """Record a tool execution for tracking and stuck detection."""
        import hashlib, json
        # Create a deterministic hash of the input parameters
        param_str = json.dumps(input_params, sort_keys=True, default=str)
        input_hash = hashlib.md5(param_str.encode()).hexdigest()

        self._execution_history.append(ExecutionRecord(
            tool_name=tool_name,
            input_hash=input_hash,
            execution_id=execution_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
        ))
        self._tool_executions += 1

    def record_investigation_iteration(self) -> None:
        """Record one pass through the investigation queue."""
        self._investigation_iterations += 1

    def check_tool_budget(self) -> dict:
        """Check if tool execution budget is available.

        Returns:
            {"allowed": bool, "used": int, "remaining": int, "max": int, "warning": bool, "message": str}
        """
        used = self._tool_executions
        remaining = self.max_tool_executions - used
        warning = used >= (self.max_tool_executions * self.warning_threshold)
        allowed = remaining > 0

        message = ""
        if not allowed:
            message = f"Tool execution budget exhausted ({used}/{self.max_tool_executions}). Produce partial report."
        elif warning:
            message = f"Tool execution budget warning: {used}/{self.max_tool_executions} used ({remaining} remaining)."
            if message not in self._warnings_issued:
                self._warnings_issued.append(message)

        return {
            "allowed": allowed,
            "used": used,
            "remaining": remaining,
            "max": self.max_tool_executions,
            "warning": warning,
            "message": message,
        }

    def check_investigation_budget(self) -> dict:
        """Check if investigation iteration budget is available.

        Returns:
            {"allowed": bool, "iterations": int, "max": int, "message": str}
        """
        allowed = self._investigation_iterations < self.max_investigation_iterations
        message = ""
        if not allowed:
            message = f"Investigation iteration cap reached ({self._investigation_iterations}/{self.max_investigation_iterations}). Remaining tasks deferred."

        return {
            "allowed": allowed,
            "iterations": self._investigation_iterations,
            "max": self.max_investigation_iterations,
            "message": message,
        }

    def check_queue_depth(self, current_depth: int) -> dict:
        """Check if investigation queue is within bounds.

        Returns:
            {"allowed": bool, "depth": int, "max": int, "message": str}
        """
        allowed = current_depth <= self.max_queue_depth
        message = ""
        if not allowed:
            message = f"Investigation queue depth exceeded ({current_depth}/{self.max_queue_depth}). Prioritize and defer low-priority tasks."

        return {
            "allowed": allowed,
            "depth": current_depth,
            "max": self.max_queue_depth,
            "message": message,
        }

    def check_stuck(self) -> dict:
        """Detect if the agent is stuck in a loop.

        Stuck = same tool with same input parameters executed twice.

        Returns:
            {"stuck": bool, "duplicates": list[dict], "message": str}
        """
        seen: dict[str, ExecutionRecord] = {}  # key = tool_name + input_hash
        duplicates = []

        for record in self._execution_history:
            key = f"{record.tool_name}:{record.input_hash}"
            if key in seen:
                dup = {
                    "tool_name": record.tool_name,
                    "first_execution": seen[key].execution_id,
                    "duplicate_execution": record.execution_id,
                }
                duplicates.append(dup)
                if dup not in self._stuck_detections:
                    self._stuck_detections.append(dup)
            else:
                seen[key] = record

        stuck = len(duplicates) > 0
        message = ""
        if stuck:
            message = f"Stuck detection: {len(duplicates)} duplicate tool execution(s) found. Skip repeated calls."

        return {
            "stuck": stuck,
            "duplicates": duplicates,
            "message": message,
        }

    def get_status(self) -> dict:
        """Get full safeguards status for the agent."""
        return {
            "tool_budget": self.check_tool_budget(),
            "investigation_budget": self.check_investigation_budget(),
            "stuck_detection": self.check_stuck(),
            "warnings_issued": list(self._warnings_issued),
            "total_stuck_detections": len(self._stuck_detections),
        }

    def get_coverage_gaps(self) -> list[str]:
        """Generate coverage gap descriptions for the report.

        Returns a list of gap descriptions based on what limits were hit.
        """
        gaps = []

        budget = self.check_tool_budget()
        if not budget["allowed"]:
            gaps.append(f"Tool execution budget exhausted at {budget['used']}/{budget['max']}. Some analysis steps may not have been performed.")

        inv = self.check_investigation_budget()
        if not inv["allowed"]:
            gaps.append(f"Investigation iteration cap reached at {inv['iterations']}/{inv['max']}. Remaining investigation tasks were deferred.")

        stuck = self.check_stuck()
        if stuck["stuck"]:
            gaps.append(f"Stuck loop detected: {len(stuck['duplicates'])} duplicate tool execution(s) were skipped.")

        return gaps
