"""Evidence Data Normalizer

Normalizes forensic data formats for consistent comparison across tools.
Used by the MCP server during output parsing and by the Tool Output Fidelity
validator for field-aware matching.
"""

import re
from datetime import datetime, timezone


def normalize_timestamp(ts: str) -> str | None:
    """Normalize a timestamp string to ISO 8601 UTC format.

    Handles common forensic timestamp formats:
    - ISO 8601 variants (with/without Z, with/without microseconds)
    - Space-separated datetime (2024-03-15 02:14:33)
    - US date format (03/15/2024 02:14:33)
    - Windows FILETIME epoch strings

    Returns normalized ISO 8601 string or None if unparseable.
    """
    if not ts or not isinstance(ts, str):
        return None

    ts = ts.strip()

    # Try ISO 8601 first (most common in forensic tools)
    try:
        cleaned = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except (ValueError, TypeError):
        pass

    # Try US date format: MM/DD/YYYY HH:MM:SS
    try:
        match = re.match(r'(\d{1,2})/(\d{1,2})/(\d{4})\s+(\d{2}):(\d{2}):(\d{2})', ts)
        if match:
            m, d, y, hr, mn, sc = match.groups()
            dt = datetime(int(y), int(m), int(d), int(hr), int(mn), int(sc), tzinfo=timezone.utc)
            return dt.isoformat()
    except (ValueError, TypeError):
        pass

    # Try Windows FILETIME (100-nanosecond intervals since 1601-01-01)
    try:
        if ts.isdigit() and len(ts) > 15:
            filetime = int(ts)
            # FILETIME epoch: Jan 1, 1601. Unix epoch: Jan 1, 1970.
            # Difference: 11644473600 seconds
            unix_ts = (filetime / 10_000_000) - 11644473600
            dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
            if dt.year >= 1980 and dt.year <= 2100:  # sanity check
                return dt.isoformat()
    except (ValueError, TypeError, OSError, OverflowError):
        pass

    return None


def normalize_path(path: str) -> str:
    """Normalize a filesystem path to a consistent format.

    - Replaces backslashes with forward slashes
    - Strips drive letter prefix (C:/ -> /)
    - Lowercases for comparison (Windows paths are case-insensitive)
    - Strips common Windows prefixes (\\Device\\HarddiskVolume, \\SystemRoot, etc.)
    """
    if not path or not isinstance(path, str):
        return ""

    normalized = path.strip()

    # Strip known Windows prefixes
    prefixes_to_strip = [
        (r'\\Device\\HarddiskVolume\d+\\', '/'),
        (r'\\\?\?\\[A-Za-z]:\\', '/'),
        (r'\\SystemRoot\\', '/Windows/'),
        (r'\\\?\\[A-Za-z]:\\', '/'),
    ]
    for pattern, replacement in prefixes_to_strip:
        normalized = re.sub(pattern, replacement, normalized)

    # Replace backslashes
    normalized = normalized.replace('\\', '/')

    # Strip drive letter
    if len(normalized) >= 2 and normalized[1] == ':':
        normalized = normalized[2:]

    # Lowercase for comparison
    normalized = normalized.lower()

    # Ensure starts with /
    if normalized and not normalized.startswith('/'):
        normalized = '/' + normalized

    return normalized


def normalize_hash(hash_str: str) -> str | None:
    """Normalize a hash string for comparison.

    Strips prefix (sha256:, md5:, SHA256=, etc.), lowercases, validates hex.
    Returns the bare lowercase hex string, or None if invalid.
    """
    if not hash_str or not isinstance(hash_str, str):
        return None

    cleaned = hash_str.strip().lower()

    # Strip common prefixes
    for prefix in ["sha256:", "sha-256:", "sha256=", "md5:", "md5=", "sha1:", "sha1="]:
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix):]
            break

    cleaned = cleaned.strip()

    # Validate hex
    if not re.match(r'^[0-9a-f]+$', cleaned):
        return None

    return cleaned


def normalize_offset(offset_str: str) -> int | None:
    """Normalize an offset/address to a decimal integer.

    Handles: hex (0x1A2B), decimal strings, hex without prefix.
    """
    if not offset_str or not isinstance(offset_str, str):
        return None

    cleaned = offset_str.strip().lower()

    try:
        if cleaned.startswith("0x"):
            return int(cleaned, 16)
        elif re.match(r'^[0-9a-f]+$', cleaned) and any(c in cleaned for c in 'abcdef'):
            # Looks like hex without prefix
            return int(cleaned, 16)
        else:
            return int(cleaned)
    except (ValueError, TypeError):
        return None
