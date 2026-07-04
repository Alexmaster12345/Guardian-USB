# Guardian USB — How to Run from a USB Drive

## USB Drive Layout

After copying the project to your USB drive it will look like this:

```
GUARDIAN/                        ← USB root (rename to whatever you like)
├── guardian/                    ← Python package (do not edit)
├── data/
│   ├── guardian.db              ← SQLite database (created on first run)
│   ├── reports/                 ← HTML/JSON/CSV reports saved here
│   └── vuln_db/
│       └── sample_cves.json     ← Offline CVE data
├── portable/
│   ├── linux/
│   │   └── run.sh               ← Linux launcher
│   ├── macos/
│   │   └── run.sh               ← macOS launcher
│   └── windows/
│       ├── run.bat              ← Windows CMD launcher
│       └── run.ps1             ← Windows PowerShell launcher
├── requirements.txt
├── pyproject.toml
└── .env                         ← Your API key lives here (create from .env.example)
```

---

## Prerequisites (installed on the host machine, NOT on the USB)

| OS | Minimum |
|----|---------|
| Linux | Python 3.11+, `nmap` (optional but recommended) |
| macOS | Python 3.11+ (`brew install python`), `nmap` (`brew install nmap`) |
| Windows | Python 3.11+ from python.org (check "Add to PATH"), `nmap` from nmap.org (optional) |

The launcher will install all Python dependencies into a `.venv-<os>` folder
**on the USB drive itself** on first run — no installation needed on the host.

---

## Step 1 — Copy project to USB

```bash
# On Linux/macOS
cp -r /home/alex/Guardian-USB /media/YOUR_USB/GUARDIAN

# Or use your file manager / Windows Explorer
```

---

## Step 2 — Create your .env file

```bash
cp .env.example .env
# Edit .env and set GUARDIAN_API_KEY to a strong random value:
# GUARDIAN_API_KEY=your-secret-key-here
```

---

## Step 3 — Run on Linux

```bash
# Open a terminal, then:
bash /media/GUARDIAN/portable/linux/run.sh --help

# First run bootstraps the venv automatically (~30 seconds)
```

---

## Step 4 — Run on macOS

```bash
# Open Terminal, then:
bash /Volumes/GUARDIAN/portable/macos/run.sh --help
```

---

## Step 5 — Run on Windows

**Option A — CMD (double-click or type):**
```
D:\portable\windows\run.bat
```

**Option B — PowerShell:**
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned   # one time only
& "D:\portable\windows\run.ps1"
```

---

## Common commands

```bash
# Update vulnerability database from NVD (needs internet)
guardian update --online

# Discover all hosts on a network
guardian discover --range 192.168.1.0/24

# Scan a specific host
guardian scan --target 192.168.1.10 --type full

# Scan all previously discovered assets
guardian scan --type full

# Generate HTML report
guardian report --format html --output ./data/reports/report.html

# Generate CSV for spreadsheet
guardian report --format csv --output ./data/reports/report.csv

# Start REST API on port 8000
guardian serve --port 8000

# List all discovered assets
guardian assets

# Offline CVE import (air-gapped environments)
guardian update --offline --file ./data/vuln_db/sample_cves.json
```

---

## Quick one-shot scan (Linux/macOS)

```bash
bash /media/GUARDIAN/portable/shared/quick-scan.sh 192.168.1.0/24
```

This discovers assets, scans them, and saves an HTML report — all in one command.

---

## Notes

- The SQLite database (`data/guardian.db`) and all reports stay **on the USB drive**
- The `.venv-linux` / `.venv-macos` / `.venv-windows` folders are created on the USB on first run — they are large (~200 MB) but only created once
- Network scanning (nmap) may require `sudo` on Linux/macOS:
  ```bash
  sudo bash /media/GUARDIAN/portable/linux/run.sh discover --range 192.168.1.0/24
  ```
- On Windows, run CMD or PowerShell **as Administrator** for full network scan capabilities
