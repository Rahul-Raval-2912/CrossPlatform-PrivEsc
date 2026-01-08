#!/bin/bash

# PrivEsc-Framework Linux Runner
# Professional Privilege Escalation Enumeration

echo "================================================"
echo "PrivEsc-Framework v1.0 - Linux Edition"
echo "Professional Privilege Escalation Enumeration"
echo "================================================"
echo

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 is not installed"
    echo "[!] Please install Python 3: sudo apt install python3 (Ubuntu/Debian)"
    echo "[!]                          sudo yum install python3 (CentOS/RHEL)"
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "main.py" ]; then
    echo "[!] main.py not found in current directory"
    echo "[!] Please run this script from the PrivEsc-Framework directory"
    exit 1
fi

echo "[+] Python 3 found, starting framework..."
echo

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "[!] Running as root - full system access available"
else
    echo "[*] Running as user: $(whoami)"
    echo "[*] Some checks may require root privileges for complete results"
fi

echo

# Run the framework
python3 main.py -f txt

echo
echo "[+] Scan completed. Check the output above for findings."
echo "[+] For JSON output, run: python3 main.py -f json -o report.json"
echo "[+] For detailed analysis, review the generated report file."