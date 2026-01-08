@echo off
title PrivEsc-Framework - Windows Privilege Escalation Scanner

echo ================================================
echo PrivEsc-Framework v1.0 - Windows Edition
echo Professional Privilege Escalation Enumeration
echo ================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python is not installed or not in PATH
    echo [!] Please install Python 3.6+ from https://python.org
    echo [!] Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

REM Check if we're in the right directory
if not exist "main.py" (
    echo [!] main.py not found in current directory
    echo [!] Please run this script from the PrivEsc-Framework directory
    pause
    exit /b 1
)

echo [+] Python found, starting framework...
echo.

REM Run the framework with default settings
python main.py -f txt

echo.
echo [+] Scan completed. Check the output above for findings.
echo [+] For JSON output, run: python main.py -f json -o report.json
echo.
pause