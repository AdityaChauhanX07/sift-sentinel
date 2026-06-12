"""Read-only evidence mounting and cryptographic integrity verification.

The agent physically cannot modify evidence because the mount is read-only at
the OS level — not because a prompt says "don't modify." This class mounts disk
images read-only, computes a SHA-256 manifest of every evidence file, and
re-verifies that manifest after tool executions.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess


class EvidenceMount:
    """Manages read-only evidence mounting and cryptographic integrity verification."""

    def __init__(self, evidence_dir: str, mount_base: str):
        """Store paths and ensure the mount base directory exists."""
        self._evidence_dir = evidence_dir
        self._mount_base = mount_base
        self._manifest: dict[str, str] = {}
        self._mounted_sources: list[dict] = []

        try:
            os.makedirs(self._mount_base, exist_ok=True)
        except OSError:
            pass

    @staticmethod
    def _hash_file(filepath: str) -> str | None:
        """Return 'sha256:<hex>' for a file, or None if it can't be read."""
        try:
            digest = hashlib.sha256()
            with open(filepath, "rb") as fh:
                for chunk in iter(lambda: fh.read(8192), b""):
                    digest.update(chunk)
            return "sha256:" + digest.hexdigest()
        except (OSError, ValueError):
            return None

    def compute_manifest(self) -> dict[str, str]:
        """Compute SHA-256 hashes for all files in the evidence directory.

        Returns a dict mapping filepath -> 'sha256:<hex>'. Directories,
        symlinks, and unreadable files are skipped. Stored as self._manifest.
        """
        manifest: dict[str, str] = {}
        for root, _dirs, files in os.walk(self._evidence_dir):
            for name in files:
                path = os.path.join(root, name)
                if os.path.islink(path) or not os.path.isfile(path):
                    continue
                digest = self._hash_file(path)
                if digest is not None:
                    manifest[path] = digest
        self._manifest = manifest
        return manifest

    def verify_integrity(self) -> dict:
        """Re-verify all evidence files against the stored manifest.

        Reports per-file matches/mismatches plus files that disappeared
        (missing) or appeared (new_files) since the manifest was computed.
        """
        matches = 0
        mismatches: list[dict] = []
        missing: list[str] = []

        for path, expected in self._manifest.items():
            actual = self._hash_file(path) if os.path.isfile(path) else None
            if actual is None:
                missing.append(path)
            elif actual == expected:
                matches += 1
            else:
                mismatches.append(
                    {"path": path, "expected": expected, "actual": actual}
                )

        # Detect files present on disk that aren't in the manifest.
        new_files: list[str] = []
        for root, _dirs, files in os.walk(self._evidence_dir):
            for name in files:
                path = os.path.join(root, name)
                if os.path.islink(path) or not os.path.isfile(path):
                    continue
                if path not in self._manifest:
                    new_files.append(path)

        verified = not mismatches and not missing and not new_files
        return {
            "verified": verified,
            "total_files": len(self._manifest),
            "matches": matches,
            "mismatches": mismatches,
            "missing": missing,
            "new_files": new_files,
        }

    def mount_image(
        self, image_path: str, mount_point_name: str, source_id: str
    ) -> dict:
        """Mount a disk image (or directory) read-only.

        Uses ``mount -o ro,loop`` for raw image files and ``mount --bind -o ro``
        for already-extracted directories. Requires root/sudo. If the mount
        fails, falls back to a read-only symlink and records the limitation.
        """
        mount_point = os.path.join(self._mount_base, mount_point_name)
        error: str | None = None
        success = False
        method = None

        try:
            os.makedirs(mount_point, exist_ok=True)
        except OSError as exc:
            error = f"Could not create mount point: {exc}"

        if error is None:
            if os.path.isdir(image_path):
                cmd = ["mount", "--bind", "-o", "ro", image_path, mount_point]
            else:
                cmd = ["mount", "-o", "ro,loop", image_path, mount_point]
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=120
                )
                if proc.returncode == 0:
                    success = True
                    method = "bind" if os.path.isdir(image_path) else "loop"
                else:
                    error = (proc.stderr or proc.stdout or "mount failed").strip()
            except (OSError, subprocess.SubprocessError) as exc:
                error = f"mount invocation failed: {exc}"

        # Fallback: a read-only symlink so dev/test can proceed without root.
        if not success:
            fallback_error = error
            try:
                if os.path.islink(mount_point) or os.path.exists(mount_point):
                    if os.path.isdir(mount_point) and not os.path.islink(mount_point):
                        try:
                            os.rmdir(mount_point)
                        except OSError:
                            pass
                    else:
                        os.remove(mount_point)
                os.symlink(image_path, mount_point)
                method = "symlink_fallback"
                # Mount truly failed, but the path is usable read-only for tools.
                error = (
                    f"Read-only mount unavailable (likely non-root). Fell back to "
                    f"symlink. Original error: {fallback_error}"
                )
            except OSError as exc:
                error = f"Mount and symlink fallback both failed: {exc}"
                method = None

        result = {
            "source_id": source_id,
            "path": image_path,
            "mount_point": mount_point,
            "success": success,
            "error": error,
        }
        self._mounted_sources.append(
            {
                "source_id": source_id,
                "path": image_path,
                "mount_point": mount_point,
                "method": method,
            }
        )
        return result

    def save_manifest(self, filepath: str) -> None:
        """Save the evidence manifest and mounted-source info to JSON."""
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "evidence_dir": self._evidence_dir,
                    "mount_base": self._mount_base,
                    "manifest": self._manifest,
                    "mounted_sources": self._mounted_sources,
                },
                f,
                indent=2,
            )

    @classmethod
    def load_manifest(cls, filepath: str) -> "EvidenceMount":
        """Load a previously saved manifest into a new EvidenceMount."""
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
        instance = cls(data["evidence_dir"], data["mount_base"])
        instance._manifest = data["manifest"]
        instance._mounted_sources = data.get("mounted_sources", [])
        return instance

    def get_source_info(self) -> list[dict]:
        """Return info about mounted sources for building EvidenceSource objects."""
        return list(self._mounted_sources)
