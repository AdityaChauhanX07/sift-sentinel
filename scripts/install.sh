#!/bin/bash
# SIFT Sentinel Installer
# Installs SIFT Sentinel on a SANS SIFT Workstation
set -e

echo "=================================="
echo "  SIFT Sentinel Installer v0.1.0"
echo "=================================="
echo ""

# Check Python version
PYTHON_CMD=""
if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
    PYTHON_CMD="python"
else
    echo "Error: Python 3.10+ is required but not found."
    exit 1
fi

PY_VERSION=$($PYTHON_CMD -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$($PYTHON_CMD -c 'import sys; print(sys.version_info.major)')
PY_MINOR=$($PYTHON_CMD -c 'import sys; print(sys.version_info.minor)')

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]); then
    echo "Error: Python 3.10+ required, found $PY_VERSION"
    exit 1
fi
echo "✓ Python $PY_VERSION found"

# Check if we're on SIFT Workstation (optional but noted)
if [ -f /etc/sift-version ] || dpkg -l sift 2>/dev/null | grep -q "^ii"; then
    echo "✓ SIFT Workstation detected"
    SIFT_DETECTED=true
else
    echo "⚠ SIFT Workstation not detected — forensic tools may not be available"
    echo "  Install SIFT: https://github.com/sans-dfir/sift"
    SIFT_DETECTED=false
fi

# Get the directory where this script lives
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo ""
echo "Installing SIFT Sentinel from: $PROJECT_DIR"
echo ""

# Install in development mode
cd "$PROJECT_DIR"
$PYTHON_CMD -m pip install -e . --break-system-packages 2>/dev/null || $PYTHON_CMD -m pip install -e .

echo ""
echo "✓ SIFT Sentinel installed successfully"
echo ""
echo "Usage:"
echo "  sift-sentinel --evidence /path/to/evidence --output /path/to/output"
echo "  sift-sentinel --resume /path/to/output"
echo "  sift-sentinel --help"
echo ""

# Verify installation
if command -v sift-sentinel &>/dev/null; then
    echo "✓ 'sift-sentinel' command is available"
else
    echo "⚠ 'sift-sentinel' not found on PATH — you may need to add ~/.local/bin to PATH:"
    echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi
