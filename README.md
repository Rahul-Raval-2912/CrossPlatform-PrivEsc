# PrivEsc-Framework v2.0

**Cross-Platform Privilege Escalation Enumeration Framework**

Automated toolkit for identifying privilege escalation opportunities across Linux and Windows systems.

## 🚀 Quick Start

### Windows
```cmd
run_windows.bat
```

### Linux
```bash
chmod +x run_linux.sh && ./run_linux.sh
```

## 🎯 Features

- **Cross-Platform**: Linux and Windows support
- **Container Security**: Docker, LXC, Kubernetes analysis
- **Network Analysis**: SSH, NFS, SNMP misconfigurations
- **Active Directory**: Kerberos, LAPS, GPP analysis
- **Exploit Suggestions**: CVE mapping with PoC links
- **Professional Reports**: JSON and text output formats

## 📊 Sample Output

```
🎯 RISK ASSESSMENT
Overall Risk Score: 8.2/10.0
Risk Level: CRITICAL RISK
Total Findings: 15

📈 FINDINGS SUMMARY
🔴 Critical: 3  🟡 High: 6  🔵 Medium: 4  🟢 Low: 2

🎯 EXPLOIT SUGGESTIONS
[01] DIRTY_PIPE (CVE-2022-0847)
     Exploit: https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
```

## 📁 Usage

```bash
# Basic scan
python main.py -f txt

# Advanced scan with exploits
python main.py -f txt -e

# JSON output
python main.py -f json -o report.json

# Build executable
python build_exe.py
```

## 🛡️ MITRE ATT&CK Coverage

- T1068: Exploitation for Privilege Escalation
- T1548: Abuse Elevation Control Mechanism
- T1053: Scheduled Task/Job
- T1574: Hijack Execution Flow
- T1134: Access Token Manipulation

## 🚀 Future Roadmap

- **AI Explanations**: Simple vulnerability explanations for all users
- **Interactive Fixes**: Step-by-step remediation guidance
- **Web Dashboard**: Visual security posture tracking
- **Cloud Platforms**: AWS, Azure, GCP support
- **Mobile Analysis**: Android and iOS security checks

## ⚖️ Legal Notice

For authorized security testing only. Use responsibly.

## 📄 License

MIT License

---

**PrivEsc-Framework v2.0** - Security made simple.