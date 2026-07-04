#!/usr/bin/env bash
# Guardian USB — Linux launcher
# Plug in USB, open terminal, run: bash /media/GUARDIAN/portable/linux/run.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USB_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENV="$USB_ROOT/.venv-linux"
PYTHON="python3"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   Guardian USB — Vulnerability Scanner   ║"
echo "║   Running on: Linux                      ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] python3 not found. Install it with:"
    echo "  sudo apt install python3 python3-pip python3-venv   # Debian/Ubuntu"
    echo "  sudo dnf install python3 python3-pip               # RHEL/Rocky/Fedora"
    exit 1
fi

PYVER=$(python3 -c "import sys; print(sys.version_info.minor)")
if [ "$PYVER" -lt 11 ]; then
    echo "[ERROR] Python 3.11+ required. Found: $(python3 --version)"
    exit 1
fi

# Bootstrap venv on first run
if [ ! -d "$VENV" ]; then
    echo "[*] First run — setting up environment (takes ~30 seconds)..."
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install --quiet --upgrade pip
    "$VENV/bin/pip" install --quiet -r "$USB_ROOT/requirements.txt"
    "$VENV/bin/pip" install --quiet -e "$USB_ROOT"
    echo "[✓] Environment ready."
fi

# Load .env if present
ENV_FILE="$USB_ROOT/.env"
if [ -f "$ENV_FILE" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
fi

# Default API key prompt if not set
if [ -z "$GUARDIAN_API_KEY" ]; then
    echo "[!] GUARDIAN_API_KEY not set."
    read -rp "    Enter API key (or press Enter to generate one): " KEY
    if [ -z "$KEY" ]; then
        KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
        echo "    Generated: $KEY"
        echo "    Save this to $USB_ROOT/.env as: GUARDIAN_API_KEY=$KEY"
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
