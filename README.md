# Guardian USB — Vulnerability Management Platform

> A portable, self-contained vulnerability management platform that runs directly from a USB drive on Linux, macOS, and Windows. No installation required on the host machine.

---

## What it does

Guardian USB is a full vulnerability management lifecycle tool — not just a scanner. It continuously discovers assets, identifies vulnerabilities, calculates risk, tracks remediation, and generates reports.

```
Discover Assets → Identify Software & Services → Detect Vulnerabilities
      ↓
Calculate Risk → Prioritize Fixes → Track Remediation → Verify → Report
```

---

## Features

| Module | Description |
|--------|-------------|
| **Asset Discovery** | Network scan (nmap + TCP fallback), collects hostname, IP, MAC, OS, CPU, memory, disk, owner |
| **Software Inventory** | Installed packages via SSH (Linux/macOS) or local package manager |
| **Service Discovery** | Detects HTTP, HTTPS, SSH, FTP, SMB, RDP, LDAP, DNS, SMTP, SNMP and more |
| **Vulnerability Detection** | CPE fingerprinting → CVE matching → findings with CVSS scores |
| **Risk Scoring** | Custom score = CVSS + internet exposure + asset criticality + exploit availability |
| **Compliance Checks** | SSH hardening, TLS policy, password policy, firewall, disk encryption |
| **Patch Tracking** | Per-finding status: New → Confirmed → Assigned → In Progress → Resolved → Verified |
| **Offline CVE Database** | Works air-gapped — import CVE data from local JSON files |
| **Reporting** | HTML, JSON, CSV — executive summary, detailed findings, asset inventory |
| **REST API** | FastAPI with API key auth — all data accessible programmatically |
| **CLI** | Rich terminal UI with progress bars and tables |
| **Automation** | Scheduled scans, reports, and alerts via APScheduler |
| **Plugin System** | Extend with custom checks, protocols, or report formats |

---

## Quick Start

### Run from USB (no install needed)

**Linux**
```bash
bash /media/GUARDIAN/portable/linux/run.sh --help
```

**macOS**
```bash
bash /Volumes/GUARDIAN/portable/macos/run.sh --help
```

**Windows — CMD**
```
D:\portable\windows\run.bat
```

**Windows — PowerShell**
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned  # once
& "D:\portable\windows\run.ps1"
```

> First run bootstraps a Python virtual environment on the USB drive itself (~30 seconds). Nothing is installed on the host machine.

---

### Run with Docker

```bash
cp .env.example .env
# Set GUARDIAN_API_KEY in .env

docker compose up -d
```

API available at `http://localhost:8000`

---

### Run locally (development)

```bash
git clone https://github.com/Alexmaster12345/Guardian-USB.git
cd Guardian-USB

python3 -m venv .venv && source .venv/bin/activate
pip install -e .

cp .env.example .env   # set GUARDIAN_API_KEY

guardian --help
```

---

## Usage

```bash
# 1. Update vulnerability database from NVD
guardian update --online

# 2. Discover assets on a network
guardian discover --range 192.168.1.0/24

# 3. Scan a host for vulnerabilities
guardian scan --target 192.168.1.10 --type full

# 4. Generate a report
guardian report --format html --output ./data/reports/report.html

# 5. Start the REST API
guardian serve --port 8000

# 6. List discovered assets
guardian assets

# 7. Manage scheduled jobs
guardian jobs list
guardian jobs add --name "nightly" --cron "0 2 * * *" --type full
```

### Quick one-shot scan (Linux / macOS)
```bash
bash portable/shared/quick-scan.sh 192.168.1.0/24
# Discovers hosts → scans → saves HTML report in one command
```

### Offline / air-gapped environments
```bash
# Import CVE data from a local file (no internet needed)
guardian update --offline --file ./data/vuln_db/sample_cves.json
```

---

## Risk Score Formula

```
Risk Score = min(10.0,
    CVSS_base × 0.4
  + Internet_Exposure × 1.5      (2.0 if exposed, 0.5 if internal)
  + Criticality_Weight × 1.5     (Critical=2.0, High=1.5, Medium=1.0, Low=0.5)
  + Exploit_Available × 1.5      (1.5 if exploit exists)
  + Actively_Exploited × 2.0     (2.0 if exploited in the wild)
)
```

Example:

| Asset | CVSS | Criticality | Internet-Facing | Exploit | Final Score |
|-------|------|-------------|-----------------|---------|-------------|
| Web Server | 8.5 | High | Yes | Yes | **9.8** |
| Test VM | 8.5 | Low | No | No | 6.4 |
| Database | 6.5 | Critical | No | Yes | **9.0** |

---

## REST API

```bash
# Health check
curl http://localhost:8000/health

# List assets (requires API key)
curl -H "X-API-Key: your-key" http://localhost:8000/assets

# Start a scan
curl -X POST -H "X-API-Key: your-key" \
     -H "Content-Type: application/json" \
     -d '{"target": "192.168.1.10", "scan_type": "full"}' \
     http://localhost:8000/scans

# Get findings
curl -H "X-API-Key: your-key" http://localhost:8000/vulnerabilities

# Generate report
curl -H "X-API-Key: your-key" http://localhost:8000/reports?format=html
```

---

## Project Structure

```
Guardian-USB/
├── guardian/
│   ├── core/                  # Config, ORM models, Pydantic schemas
│   ├── discovery/             # Network scanner, asset/software/service collector
│   ├── fingerprinting/        # OS, service, CPE fingerprinting
│   ├── vulnerability_engine/  # CVE matching, TLS/service/config checks
│   ├── risk_engine/           # Risk scoring and prioritization
│   ├── compliance/            # SSH, TLS, password, firewall, encryption checks
│   ├── reporting/             # HTML/JSON/CSV report generation
│   ├── automation/            # Scheduled jobs (APScheduler)
│   ├── plugins/               # Plugin base class and dynamic loader
│   ├── database/              # SQLAlchemy repositories
│   ├── updates/               # NVD sync and offline import
│   ├── api/                   # FastAPI REST API
│   └── cli/                   # Typer CLI
├── portable/
│   ├── linux/run.sh           # Linux USB launcher
│   ├── macos/run.sh           # macOS USB launcher
│   ├── windows/run.bat        # Windows CMD launcher
│   ├── windows/run.ps1        # Windows PowerShell launcher
│   └── shared/quick-scan.sh   # One-shot discover+scan+report
├── data/
│   ├── guardian.db            # SQLite database (created on first run)
│   ├── reports/               # Generated reports
│   └── vuln_db/               # Offline CVE data
├── tests/                     # pytest test suite
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

---

## Requirements

**Host machine (USB mode):**
- Python 3.11+
- `nmap` (optional — falls back to TCP connect scan)
- `sudo` / Administrator for raw network scans

**Python dependencies** (auto-installed into `.venv-<os>` on the USB):

`sqlalchemy` `fastapi` `uvicorn` `pydantic` `typer` `rich` `jinja2` `requests` `apscheduler` `paramiko` `cryptography` `python-nmap` `httpx`

---

## Configuration

Copy `.env.example` to `.env` and set your values:

```env
# Required
GUARDIAN_API_KEY=your-strong-secret-here

# Database (default: SQLite on USB)
GUARDIAN_DB_URL=sqlite:////path/to/data/guardian.db

# Optional: NVD API key for higher rate limits
# Register free at: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=

# API server
GUARDIAN_HOST=127.0.0.1
GUARDIAN_PORT=8000
```

---

## Writing a Plugin

```python
from guardian.plugins.base import PluginBase
from guardian.core.models import Asset, Finding

class MyPlugin(PluginBase):
    name = "my-plugin"

    def on_asset_discovered(self, asset: Asset) -> None:
        print(f"New asset: {asset.hostname}")

    def on_finding(self, finding: Finding) -> None:
        if finding.severity == "Critical":
            # send alert, create ticket, etc.
            pass

    def on_scan_complete(self, scan, findings: list[Finding]) -> None:
        print(f"Scan done: {len(findings)} findings")
```

Drop the file into `guardian/plugins/` — it is loaded automatically.

---

## License

MIT — free to use, modify, and distribute.

---

> Guardian USB is designed to grow over time — more OS support, more protocols, more compliance frameworks, attack-path analysis, and AI-assisted remediation suggestions. The modular architecture means new capabilities can be added without redesigning the core.
