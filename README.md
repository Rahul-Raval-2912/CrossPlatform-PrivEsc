# PrivEsc-Framework v2.0

**🚀 Advanced Cross-Platform Privilege Escalation Enumeration Framework**

A comprehensive, automated toolkit for identifying privilege escalation opportunities across Linux and Windows systems. Designed for penetration testers, security auditors, and red/blue team operations.

## 🚀 Quick Start

### Windows (No Python Knowledge Required)
```cmd
# Just double-click!
run_windows.bat

# Advanced scan with exploits
python main.py -f txt -e
```

### Linux
```bash
# One command setup and run
chmod +x run_linux.sh && ./run_linux.sh

# Advanced scan with exploits
python3 main.py -f txt -e
```

## 🎯 Advanced Features v2.0

### 🐳 **Container Security**
- **Docker Escape Detection**: Privileged containers, socket access
- **LXC/LXD Analysis**: Container group memberships
- **Kubernetes Enumeration**: Service account tokens, RBAC issues
- **Runtime Vulnerabilities**: runc, containerd CVE detection

### 🌐 **Network Analysis**
- **Service Enumeration**: Dangerous localhost services
- **SSH Misconfigurations**: Root login, weak authentication
- **NFS Security**: no_root_squash detection
- **SNMP Analysis**: Default community strings

### 🏢 **Active Directory (Windows)**
- **Kerberos Tickets**: Golden/Silver ticket opportunities
- **LAPS Detection**: Local admin password management
- **Group Policy**: GPP password extraction
- **DCSync Privileges**: Domain controller replication rights

### 💥 **Exploit Suggestions**
- **CVE Database**: Kernel exploit matching
- **GTFOBins Integration**: SUID binary exploitation
- **PoC Links**: Direct links to working exploits
- **Severity Scoring**: Risk-based prioritization

## 📊 Sample Advanced Output

```
╔════════════════════════════════════════════════════════════════════╗
║           PRIVESC-FRAMEWORK v2.0 SECURITY ASSESSMENT              ║
╚════════════════════════════════════════════════════════════════════╝

🎯 RISK ASSESSMENT
──────────────────────────────────────────────────────
Overall Risk Score: 8.2/10.0
Risk Level:         CRITICAL RISK - Immediate attention required
Total Findings:     15
Exploit Suggestions: 3

📈 FINDINGS SUMMARY
──────────────────────────────────────────────────────
🔴 Critical:   3
🟡 High:       6
🔵 Medium:     4
🟢 Low:        2

🎯 EXPLOIT SUGGESTIONS
══════════════════════════════════════════════════════════════════════

[01] DIRTY_PIPE
     Severity: Critical
     CVE: CVE-2022-0847
     Description: Arbitrary file write vulnerability
     Exploit Code: https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits

[02] DOCKER_SOCKET_ESCAPE
     Severity: Critical
     Description: Docker socket accessible - container escape possible
     Command: docker run -v /:/host -it ubuntu chroot /host bash
```

## 🔍 Enhanced Detection Capabilities

### Linux Advanced
- **Container Escapes**: Docker, LXC, Kubernetes privilege escalation
- **Network Services**: SSH, NFS, SNMP misconfigurations
- **Kernel Exploits**: CVE-2022-0847 (Dirty Pipe), CVE-2021-4034 (PwnKit)
- **Advanced SUID**: GTFOBins integration with exploit commands
- **Systemd Analysis**: Timer and service vulnerabilities

### Windows Advanced
- **Active Directory**: Kerberos attacks, LAPS bypass, GPP extraction
- **Container Support**: Windows containers and Hyper-V detection
- **Advanced Registry**: Credential extraction, UAC bypass techniques
- **Token Analysis**: Dangerous privileges with exploitation paths
- **Service Exploits**: Unquoted paths with automated exploitation

## 📁 Advanced Usage

```bash
# Basic professional scan
python main.py -f txt

# Advanced scan with exploit suggestions
python main.py -f txt -e

# JSON output for SIEM integration
python main.py -f json -o security_report.json

# Complete assessment with exploits
python main.py -f txt -e -o full_assessment.txt

# Build standalone executable
python build_exe.py
```

## 🔧 Enterprise Features

### **SIEM Integration**
```json
{
  "metadata": {
    "framework": "PrivEsc-Framework v2.0",
    "overall_risk_score": 8.2,
    "exploit_suggestions_count": 3
  },
  "findings": [...],
  "exploit_suggestions": [...]
}
```

### **Automated Deployment**
```bash
# Docker deployment
docker run -v /:/host privesc-framework

# Kubernetes job
kubectl apply -f privesc-scan-job.yaml
```

## 🛡️ MITRE ATT&CK Coverage v2.0

- **T1068**: Exploitation for Privilege Escalation
- **T1548**: Abuse Elevation Control Mechanism  
- **T1053**: Scheduled Task/Job
- **T1574**: Hijack Execution Flow
- **T1134**: Access Token Manipulation
- **T1610**: Deploy Container *(NEW)*
- **T1087**: Account Discovery *(NEW)*
- **T1046**: Network Service Scanning *(NEW)*

## 🏆 Key Features

1. **🎯 Comprehensive Coverage**: Container, network, and AD analysis
2. **🚀 User-Friendly**: One-click execution with batch/shell scripts
3. **📊 Professional Reports**: Clean, actionable output with risk scoring
4. **💥 Exploit Ready**: Direct CVE mapping and PoC links
5. **🔄 Cross-Platform**: Single tool for both Linux and Windows
6. **🎨 Modern Design**: Python-based with advanced filtering

## ⚖️ Responsible Disclosure

This tool is for **authorized security testing only**. The exploit suggestion feature should only be used by security professionals with proper authorization.

## 📄 License

MIT License - Professional security tool for the community.

---

**PrivEsc-Framework v2.0** - Advanced privilege escalation enumeration for security professionals.