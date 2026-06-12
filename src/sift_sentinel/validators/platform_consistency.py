"""Platform consistency validator.

Checks whether a finding's artifact type is consistent with the evidence
source's operating system / filesystem. A Windows registry key on a Linux ext4
image is a logical impossibility — a hallucination, not a real finding.
"""

from __future__ import annotations

import re

from .base import BaseValidator, ValidatorVerdict
from ..evidence_graph.models import Finding


# Filesystem -> platform hints
_NTFS = ("ntfs",)
_LINUX_FS = ("ext2", "ext3", "ext4", "xfs", "btrfs")
_MACOS_FS = ("apfs", "hfs", "hfs+")

# Windows-only path/category indicators (all lowercase)
_WINDOWS_PATH_SUBSTRINGS = (
    "\\windows\\",
    "\\system32\\",
    "\\syswow64\\",
    "\\users\\",
    "\\programdata\\",
    "\\program files",
    "\\appdata\\",
    "ntuser.dat",
    "system32\\config\\",
    "$mft",
    "$usnjrnl",
    "software\\microsoft\\",
    "\\run\\",
)
_WINDOWS_PATH_SUFFIXES = (".evtx", ".pf", ".lnk")
_WINDOWS_CATEGORIES = ("registry_artifact", "prefetch", "amcache")
_DRIVE_LETTER_RE = re.compile(r"^[a-z]:\\")

# Linux-only path indicators (all lowercase)
_LINUX_PATH_PREFIXES = (
    "/etc/",
    "/var/log/",
    "/usr/",
    "/home/",
    "/tmp/",
    "/proc/",
    "/sys/",
)
_LINUX_PATH_SUBSTRINGS = ("/cron", "syslog", ".bash_history", "/systemd/", "/init.d/")

# macOS-only path indicators (lowercase form of the documented patterns)
_MACOS_PATH_SUBSTRINGS = (
    "/library/",
    ".plist",
    "/applications/",
    "/.spotlight-",
    "/fseventsd",
)


class PlatformConsistencyValidator(BaseValidator):
    """Validates that an artifact could plausibly exist on its evidence source's platform."""

    @property
    def name(self) -> str:
        """Identifier used as ValidationResult.validator_name."""
        return "platform_consistency"

    @property
    def description(self) -> str:
        """One-line description of the check."""
        return (
            "Checks whether artifact type is consistent with the evidence "
            "source OS/filesystem"
        )

    def validate(self, finding: Finding, context: dict):
        """Return a ValidationResult comparing the artifact against its source platform."""
        try:
            return self._validate(finding, context)
        except Exception as exc:  # never crash — degrade to NOT_APPLICABLE
            return self._make_result(
                ValidatorVerdict.NOT_APPLICABLE,
                f"Validator error, treated as not applicable: {exc}",
            )

    def _validate(self, finding: Finding, context: dict):
        anchor = finding.evidence_anchor
        if anchor is None:
            return self._make_result(
                ValidatorVerdict.NOT_APPLICABLE,
                "No evidence anchor — cannot check platform consistency.",
            )

        source = self._find_source(anchor.source_id, context)
        if source is None:
            return self._make_result(
                ValidatorVerdict.NOT_APPLICABLE,
                f"Evidence source {anchor.source_id} not found in context.",
            )

        metadata = source.get("metadata") or {}
        os_type = metadata.get("os_type")
        filesystem_type = metadata.get("filesystem_type")
        if os_type is None and filesystem_type is None:
            return self._make_result(
                ValidatorVerdict.NOT_APPLICABLE,
                f"No OS or filesystem metadata available for source {anchor.source_id}.",
            )

        platform = self._determine_platform(os_type, filesystem_type)
        if platform is None:
            return self._make_result(
                ValidatorVerdict.NOT_APPLICABLE,
                f"Unrecognized platform: os_type={os_type}, "
                f"filesystem_type={filesystem_type}",
            )

        artifact_path = anchor.artifact_path
        path_lower = artifact_path.lower() if artifact_path else ""
        category_lower = (finding.category or "").lower()

        # An artifact that looks like it belongs to a *different* platform than
        # the source is a logical impossibility.
        if platform != "windows" and self._is_windows_artifact(path_lower, category_lower):
            return self._mismatch("Windows", artifact_path, finding.category, platform)
        if platform != "linux" and self._is_linux_artifact(path_lower):
            return self._mismatch("Linux", artifact_path, finding.category, platform)
        if platform != "macos" and self._is_macos_artifact(path_lower):
            return self._mismatch("macOS", artifact_path, finding.category, platform)

        return self._make_result(
            ValidatorVerdict.PASS,
            f"Artifact is consistent with {platform} evidence source.",
        )

    # --- helpers ---

    @staticmethod
    def _find_source(source_id: str, context: dict) -> dict | None:
        for source in context.get("evidence_sources", []) or []:
            if source.get("source_id") == source_id:
                return source
        return None

    @staticmethod
    def _determine_platform(os_type, filesystem_type) -> str | None:
        os_lower = os_type.lower() if isinstance(os_type, str) else ""
        fs_lower = filesystem_type.lower() if isinstance(filesystem_type, str) else ""

        if "windows" in os_lower or fs_lower in _NTFS:
            return "windows"
        if "linux" in os_lower or fs_lower in _LINUX_FS:
            return "linux"
        if "macos" in os_lower or "darwin" in os_lower or fs_lower in _MACOS_FS:
            return "macos"
        return None

    @staticmethod
    def _is_windows_artifact(path_lower: str, category_lower: str) -> bool:
        if category_lower in _WINDOWS_CATEGORIES:
            return True
        if not path_lower:
            return False
        if _DRIVE_LETTER_RE.match(path_lower):
            return True
        if any(sub in path_lower for sub in _WINDOWS_PATH_SUBSTRINGS):
            return True
        if path_lower.endswith(_WINDOWS_PATH_SUFFIXES):
            return True
        return False

    @staticmethod
    def _is_linux_artifact(path_lower: str) -> bool:
        if not path_lower:
            return False
        if path_lower.startswith(_LINUX_PATH_PREFIXES):
            return True
        if any(sub in path_lower for sub in _LINUX_PATH_SUBSTRINGS):
            return True
        return False

    @staticmethod
    def _is_macos_artifact(path_lower: str) -> bool:
        if not path_lower:
            return False
        return any(sub in path_lower for sub in _MACOS_PATH_SUBSTRINGS)

    def _mismatch(self, artifact_platform: str, artifact_path, category: str, platform: str):
        return self._make_result(
            ValidatorVerdict.FAIL_HARD,
            f"{artifact_platform} artifact '{artifact_path}' (category: {category}) "
            f"found on {platform} evidence source — logical impossibility.",
        )
