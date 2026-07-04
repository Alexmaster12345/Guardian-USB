@echo off
:: Guardian USB — Windows launcher
:: Plug in USB, open Command Prompt, run: D:\portable\windows\run.bat
:: Or double-click run.bat from Explorer

setlocal EnableDelayedExpansion

echo.
echo  +==========================================+
echo  ^|  Guardian USB - Vulnerability Scanner   ^|
echo  ^|  Running on: Windows                    ^|
echo  +==========================================+
echo.

:: Resolve USB root (two levels up from this script)
set "SCRIPT_DIR=%~dp0"
set "USB_ROOT=%SCRIPT_DIR%..\..\"
for %%i in ("%USB_ROOT%") do set "USB_ROOT=%%~fi"

set "VENV=%USB_ROOT%.venv-windows"
set "DB_PATH=%USB_ROOT%data\guardian.db"
set "REPORT_DIR=%USB_ROOT%data\reports"

:: Find Python
set "PYTHON="
for %%P in (python python3) do (
    where %%P >nul 2>&1 && set "PYTHON=%%P" && goto :found_python
)
echo [ERROR] Python not found. Install from https://python.org
echo         Make sure to check "Add Python to PATH" during install.
pause
exit /b 1

:found_python
:: Check version >= 3.11
for /f "tokens=2 delims= " %%V in ('!PYTHON! --version 2^>^&1') do set "PYVER=%%V"
echo [*] Found Python !PYVER!

:: Bootstrap venv
if not exist "%VENV%\Scripts\guardian.exe" (
    echo [*] First run - setting up environment, please wait...
    !PYTHON! -m venv "%VENV%"
    "%VENV%\Scripts\pip" install --quiet --upgrade pip
    "%VENV%\Scripts\pip" install --quiet -r "%USB_ROOT%requirements.txt"
    "%VENV%\Scripts\pip" install --quiet -e "%USB_ROOT%"
    echo [OK] Environment ready.
)

:: Load .env if present
if exist "%USB_ROOT%.env" (
    for /f "usebackq tokens=1,* delims==" %%A in ("%USB_ROOT%.env") do (
        set "%%A=%%B"
    )
)

:: API key
if "%GUARDIAN_API_KEY%"=="" (
    echo [!] GUARDIAN_API_KEY not set.
    set /p "GUARDIAN_API_KEY=    Enter API key: "
)

set "GUARDIAN_DB_URL=sqlite:///%DB_PATH:\=/%"
set "GUARDIAN_REPORT_DIR=%REPORT_DIR%"

echo.
echo Usage examples:
echo   guardian discover --range 192.168.1.0/24
echo   guardian scan --target 192.168.1.1 --type full
echo   guardian report --format html --output "%REPORT_DIR%\report.html"
echo   guardian update --online
echo   guardian serve --port 8000
echo.

:: If no args given, drop into interactive mode
if "%~1"=="" (
    echo No command given. Starting interactive shell...
    echo Type 'guardian --help' to see all commands.
    cmd /k "set PATH=%VENV%\Scripts;%PATH% && echo Guardian USB ready."
) else (
    "%VENV%\Scripts\guardian.exe" %*
)
