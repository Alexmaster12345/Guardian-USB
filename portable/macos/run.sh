#!/usr/bin/env bash
# Guardian USB — macOS launcher
# Plug in USB, open Terminal, run: bash /Volumes/GUARDIAN/portable/macos/run.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USB_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENV="$USB_ROOT/.venv-macos"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   Guardian USB — Vulnerability Scanner   ║"
echo "║   Running on: macOS                      ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Try python3 from Homebrew first, then system
PYTHON=""
for candidate in /opt/homebrew/bin/python3 /usr/local/bin/python3 python3; do
    if command -v "$candidate" &>/dev/null; then
        PYTHON="$candidate"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "[ERROR] python3 not found."
    echo "  Install via Homebrew: brew install python3"
    echo "  Or download from: https://python.org"
    exit 1
fi

PYVER=$("$PYTHON" -c "import sys; print(sys.version_info.minor)")
if [ "$PYVER" -lt 11 ]; then
    echo "[ERROR] Python 3.11+ required. Found: $($PYTHON --version)"
    exit 1
fi

# nmap check (needed for network scanning)
if ! command -v nmap &>/dev/null; then
    echo "[!] nmap not found — network discovery will use TCP fallback."
    echo "    Install with: brew install nmap"
fi

# Bootstrap venv on first run
if [ ! -d "$VENV" ]; then
    echo "[*] First run — setting up environment (takes ~30 seconds)..."
    "$PYTHON" -m venv "$VENV"
    "$VENV/bin/pip" install --quiet --upgrade pip
    "$VENV/bin/pip" install --quiet -r "$USB_ROOT/requirements.txt"
    "$VENV/bin/pip" install --quiet -e "$USB_ROOT"
    echo "[✓] Environment ready."
fi

# Load .env if present
ENV_FILE="$USB_ROOT/.env"
if [ -f "$ENV_FILE" ]; then
    set -a
    source "$ENV_FILE"
    set +a
fi

if [ -z "$GUARDIAN_API_KEY" ]; then
    echo "[!] GUARDIAN_API_KEY not set."
    read -rp "    Enter API key (or press Enter to generate one): " KEY
    if [ -z "$KEY" ]; then
        KEY=$("$PYTHON" -c "import secrets; print(secrets.token_hex(32))")
        echo "    Generated: $KEY"
        echo "    Save to $USB_ROOT/.env as: GUARDIAN_API_KEY=$KEY"
    fi
    export GUARDIAN_API_KEY="$KEY"
fi

export GUARDIAN_DB_URL="sqlite:///$USB_ROOT/data/guardian.db"
export GUARDIAN_REPORT_DIR="$USB_ROOT/data/reports"

echo ""
echo "Usage examples:"
echo "  guardian discover --range 192.168.1.0/24"
echo "  guardian scan --target 192.168.1.1 --type full"
echo "  guardian report --format html --output $USB_ROOT/data/reports/report.html"
echo "  guardian update --online"
echo "  guardian serve --port 8000"
echo ""

exec "$VENV/bin/guardian" "$@"
