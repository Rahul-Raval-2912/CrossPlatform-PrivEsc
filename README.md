# PrivEsc-Framework

**Professional Cross-Platform Privilege Escalation Enumeration Framework**

A comprehensive, automated toolkit for identifying privilege escalation opportunities across Linux and Windows systems. Designed for penetration testers, security auditors, and red/blue team operations.

## 🚀 Quick Start

### Windows
```cmd
# Double-click to run
run_windows.bat

# Or use Python directly
python main.py -f txt
```

### Linux
```bash
# Make executable and run
chmod +x run_linux.sh && ./run_linux.sh

# Or use Python directly
python3 main.py -f txt
```

## 🎯 Features

- **Cross-Platform**: Linux and Windows support
- **Risk Scoring**: Automated severity classification (Critical/High/Medium/Low)
- **MITRE ATT&CK Mapping**: Maps findings to MITRE ATT&CK techniques
- **Professional Reporting**: JSON and human-readable text output
- **Safe Operation**: Detection only - no exploitation attempts

## 📊 Sample Output

```
╔════════════════════════════════════════════════════════════════════╗
║           PRIVESC-FRAMEWORK SECURITY ASSESSMENT REPORT            ║
╚════════════════════════════════════════════════════════════════════╝

🎯 RISK ASSESSMENT
──────────────────────────────────────────────────────
Overall Risk Score: 6.5/10.0
Risk Level:         HIGH RISK - Significant security concerns
Total Findings:     12

📈 FINDINGS SUMMARY
──────────────────────────────────────────────────────
🔴 Critical:   2
🟡 High:       4
🔵 Medium:     5
🟢 Low:        1

🔍 DETAILED FINDINGS
══════════════════════════════════════════════════════════════════════

🔴 CRITICAL SEVERITY FINDINGS
──────────────────────────────────────────────────────

[01] Dangerous SUID binary (GTFOBins): find
     Type: Suid
     MITRE ATT&CK: T1548.001 - Abuse Elevation Control Mechanism
     Risk Score: 9.0/10.0
     💡 Mitigation: Remove SUID bit: chmod u-s /usr/bin/find
```

## 🔍 Detection Capabilities

### Linux
- **SUID/SGID Analysis**: GTFOBins integration, capabilities detection
- **Sudo Misconfigurations**: NOPASSWD rules, dangerous binaries
- **Cron Vulnerabilities**: Writable scripts, systemd timers
- **Kernel Exploits**: CVE matching, outdated versions
- **User Enumeration**: Privilege groups, SSH keys

### Windows
- **Service Misconfigurations**: Unquoted paths, weak permissions
- **Registry Vulnerabilities**: AutoRun analysis, stored credentials
- **Token Privileges**: Dangerous privileges, impersonation opportunities
- **Scheduled Tasks**: High-privilege tasks, writable executables

## 📁 Usage Examples

```bash
# Basic scan with text output
python main.py -f txt

# JSON output to file
python main.py -f json -o security_report.json

# Use provided launchers (recommended)
./run_linux.sh        # Linux
run_windows.bat        # Windows
```

## 🔧 Building Executables

```bash
# Create standalone executable
python build_exe.py

# Results in dist/ directory:
# - PrivEsc-Framework-Windows.exe
# - PrivEsc-Framework-Linux
```

## 🛡️ MITRE ATT&CK Coverage

- **T1068**: Exploitation for Privilege Escalation
- **T1548**: Abuse Elevation Control Mechanism
- **T1053**: Scheduled Task/Job
- **T1574**: Hijack Execution Flow
- **T1134**: Access Token Manipulation

## ⚖️ Legal Notice

This tool is for authorized security testing and educational purposes only. Users must ensure proper authorization before scanning any systems.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.