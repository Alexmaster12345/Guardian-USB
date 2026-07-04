# Guardian USB — Windows PowerShell launcher
# Run from PowerShell: & "D:\portable\windows\run.ps1"
# If execution policy blocks it: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$UsbRoot   = Resolve-Path "$ScriptDir\..\.."
$Venv      = Join-Path $UsbRoot ".venv-windows"
$DbPath    = Join-Path $UsbRoot "data\guardian.db"
$ReportDir = Join-Path $UsbRoot "data\reports"

Write-Host ""
Write-Host "  +==========================================+" -ForegroundColor Cyan
Write-Host "  |  Guardian USB - Vulnerability Scanner   |" -ForegroundColor Cyan
Write-Host "  |  Running on: Windows (PowerShell)       |" -ForegroundColor Cyan
Write-Host "  +==========================================+" -ForegroundColor Cyan
Write-Host ""

# Find Python
$Python = Get-Command python -ErrorAction SilentlyContinue |
          Select-Object -ExpandProperty Source
if (-not $Python) {
    $Python = Get-Command python3 -ErrorAction SilentlyContinue |
              Select-Object -ExpandProperty Source
}
if (-not $Python) {
    Write-Host "[ERROR] Python not found. Install from https://python.org" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

$PyVer = & $Python --version 2>&1
Write-Host "[*] Found $PyVer"

# Bootstrap venv
$GuardianExe = Join-Path $Venv "Scripts\guardian.exe"
if (-not (Test-Path $GuardianExe)) {
    Write-Host "[*] First run — setting up environment..."
    & $Python -m venv $Venv
    & "$Venv\Scripts\pip" install --quiet --upgrade pip
    & "$Venv\Scripts\pip" install --quiet -r "$UsbRoot\requirements.txt"
    & "$Venv\Scripts\pip" install --quiet -e $UsbRoot
    Write-Host "[OK] Environment ready." -ForegroundColor Green
}

# Load .env
$EnvFile = Join-Path $UsbRoot ".env"
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match "^\s*([^#][^=]+)=(.*)$") {
            [System.Environment]::SetEnvironmentVariable($Matches[1].Trim(), $Matches[2].Trim(), "Process")
        }
    }
}

# API key
if (-not $env:GUARDIAN_API_KEY) {
    $key = Read-Host "[!] GUARDIAN_API_KEY not set. Enter API key"
    $env:GUARDIAN_API_KEY = $key
}

$env:GUARDIAN_DB_URL    = "sqlite:///" + $DbPath.Replace("\", "/")
$env:GUARDIAN_REPORT_DIR = $ReportDir

Write-Host ""
Write-Host "Usage examples:" -ForegroundColor Yellow
Write-Host "  guardian discover --range 192.168.1.0/24"
Write-Host "  guardian scan --target 192.168.1.1 --type full"
Write-Host "  guardian report --format html --output $ReportDir\report.html"
Write-Host "  guardian update --online"
Write-Host "  guardian serve --port 8000"
Write-Host ""

$env:PATH = "$Venv\Scripts;$env:PATH"

if ($args.Count -eq 0) {
    Write-Host "No command given — dropping into interactive shell." -ForegroundColor DarkGray
    Write-Host "Type 'guardian --help' to see all commands." -ForegroundColor DarkGray
    & powershell -NoExit -Command '$env:PATH = "' + "$Venv\Scripts" + ';$env:PATH"'
} else {
    & "$GuardianExe" @args
}
