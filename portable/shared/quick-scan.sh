#!/usr/bin/env bash
# Quick one-shot scan: discovers assets and runs a full vulnerability scan
# Usage: bash quick-scan.sh 192.168.1.0/24

RANGE="${1:-192.168.1.0/24}"
USB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

OS="$(uname -s)"
case "$OS" in
  Linux)  LAUNCHER="$USB_ROOT/portable/linux/run.sh" ;;
  Darwin) LAUNCHER="$USB_ROOT/portable/macos/run.sh" ;;
  *)      echo "Use run.bat or run.ps1 on Windows"; exit 1 ;;
esac

echo "[Guardian USB] Quick scan on: $RANGE"
echo ""

bash "$LAUNCHER" discover --range "$RANGE"
echo ""
echo "[*] Discovery complete. Starting vulnerability scan..."
bash "$LAUNCHER" scan --type full
echo ""
echo "[*] Generating report..."
bash "$LAUNCHER" report --format html --output "$USB_ROOT/data/reports/quick-scan-$(date +%Y%m%d-%H%M).html"
echo ""
echo "[✓] Done. Report saved to: $USB_ROOT/data/reports/"
