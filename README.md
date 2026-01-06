# PrivEsc-Framework v1.0

## Professional Cross-Platform Privilege Escalation Enumeration Framework

A comprehensive, automated toolkit for identifying privilege escalation opportunities across Linux and Windows systems. Designed for penetration testers, security auditors, and red/blue team operations.

## 🎯 Features

### Cross-Platform Support
- **Linux**: SUID/SGID analysis, capabilities, cron jobs, systemd timers, kernel vulnerabilities
- **Windows**: Service misconfigurations, registry weaknesses, token privileges, scheduled tasks

### Advanced Analysis
- **Risk Scoring**: Automated severity classification (Critical/High/Medium/Low)
- **MITRE ATT&CK Mapping**: Maps findings to MITRE ATT&CK techniques
- **Deep Enumeration**: Goes beyond basic checks with advanced detection logic
- **Professional Reporting**: JSON and human-readable text output formats

### Security Features
- **Detection Only**: No exploitation attempts - safe for production environments
- **Minimal Footprint**: Lightweight enumeration with timeout protection
- **Comprehensive Coverage**: 50+ different privilege escalation vectors

## 📁 Framework Structure

```
PrivEsc-Framework/
├── core/
│   ├── os_detector.py          # Cross-platform OS detection
│   ├── privilege_checker.py    # Current privilege assessment
│   └── report_engine.py        # Report generation with MITRE mapping
├── linux/
│   ├── enum_users.py          # User enumeration and analysis
│   ├── enum_sudo.py           # Sudo configuration analysis
│   ├── enum_suid.py           # SUID/SGID and capabilities deep scan
│   ├── enum_cron.py           # Cron jobs and systemd timers
│   └── enum_kernel.py         # Kernel vulnerability assessment
├── windows/
│   ├── enum_services.py       # Service misconfigurations
│   ├── enum_registry.py       # Registry-based vulnerabilities
│   ├── enum_tokens.py         # Token privileges and manipulation
│   └── enum_scheduled_tasks.py # Scheduled task analysis
├── rules/
│   └── risk_rules.yaml        # Risk scoring and MITRE mappings
└── main.py                    # Framework entry point
```

## 🚀 Quick Start

### Prerequisites
- Python 3.6+
- Administrative/root access (recommended for complete enumeration)
- Platform-specific tools (automatically detected)

### Installation
```bash
git clone <repository>
cd PrivEsc-Framework
chmod +x main.py
```

### Basic Usage
```bash
# Run with JSON output (default)
python3 main.py

# Generate human-readable report
python3 main.py -f txt

# Save to file
python3 main.py -f json -o privesc_report.json
python3 main.py -f txt -o privesc_report.txt

# Verbose output
python3 main.py --verbose
```

## 📊 Sample Output

### Console Summary
```
[+] PrivEsc-Framework v1.0 - Professional Privilege Escalation Enumeration
======================================================================
[+] Target OS: Linux Ubuntu 20.04.3 LTS
[+] Current User: testuser (Privileges: user)

[+] Starting enumeration modules...
[✓] linux.enum_users completed
[✓] linux.enum_sudo completed  
[✓] linux.enum_suid completed
[✓] linux.enum_cron completed
[✓] linux.enum_kernel completed

[+] Report generated: console
[+] Overall Risk Score: 7.2/10.0
```

### Detailed Findings
```json
{
  "metadata": {
    "framework": "PrivEsc-Framework v1.0",
    "scan_date": "2024-01-15T14:30:22",
    "overall_risk_score": 7.2
  },
  "findings": [
    {
      "id": 1,
      "type": "suid",
      "severity": "Critical",
      "description": "Dangerous SUID binary (GTFOBins): find",
      "mitre_attack": {
        "technique_id": "T1548.001",
        "technique_name": "Setuid and Setgid"
      },
      "risk_score": 9.0,
      "mitigation": "Remove SUID bit: chmod u-s /usr/bin/find"
    }
  ]
}
```

## 🔍 Enumeration Modules

### Linux Modules

#### enum_users.py
- Non-root users with UID 0
- World-writable home directories  
- Users in privileged groups (sudo, docker, lxd)
- SSH key misconfigurations

#### enum_sudo.py
- NOPASSWD sudo rules
- Dangerous sudo binary access
- Sudoers file permissions
- Sudo version vulnerabilities

#### enum_suid.py
- GTFOBins SUID binary detection
- File capabilities analysis
- Custom SUID binaries in unusual locations
- SGID binary enumeration

#### enum_cron.py
- System cron directory analysis
- Writable cron scripts
- Systemd timer vulnerabilities
- PATH manipulation in cron jobs

#### enum_kernel.py
- Known kernel CVE matching
- Outdated kernel detection
- Kernel module analysis
- Security parameter assessment

### Windows Modules

#### enum_services.py
- Unquoted service paths
- Weak service permissions
- AlwaysInstallElevated detection
- Writable service binaries

#### enum_registry.py
- AutoRun entry analysis
- Stored credential detection
- UAC configuration assessment
- Windows Defender exclusions

#### enum_tokens.py
- Dangerous privilege enumeration
- Token manipulation opportunities
- LSA protection status
- Credential storage analysis

#### enum_scheduled_tasks.py
- High-privilege task analysis
- Writable task executables
- Missing executable detection
- Script-based task vulnerabilities

## 🎯 MITRE ATT&CK Mapping

The framework maps findings to MITRE ATT&CK techniques:

- **T1068**: Exploitation for Privilege Escalation
- **T1548**: Abuse Elevation Control Mechanism
  - T1548.001: Setuid and Setgid
  - T1548.003: Sudo and Sudo Caching
- **T1053**: Scheduled Task/Job
  - T1053.003: Cron
  - T1053.005: Scheduled Task
- **T1574**: Hijack Execution Flow
- **T1134**: Access Token Manipulation
- **T1055**: Process Injection

## 📈 Risk Scoring

### Severity Levels
- **Critical (9.0)**: Immediate privilege escalation possible
- **High (7.0)**: Significant security risk requiring attention
- **Medium (5.0)**: Potential security weakness
- **Low (3.0)**: Minor configuration issue

### Risk Calculation
Risk scores are calculated based on:
- Finding type and context
- System location and permissions
- Potential impact assessment
- MITRE ATT&CK technique severity

## 🛡️ Security Considerations

### Safe Operation
- **Detection Only**: No exploitation attempts
- **Read-Only**: No system modifications
- **Timeout Protection**: 30-second command limits
- **Error Handling**: Graceful failure management

### Responsible Use
- Only use on systems you own or have explicit permission to test
- Designed for authorized security testing and auditing
- Educational and professional security assessment purposes

## 🔧 Customization

### Adding New Checks
1. Create new enumeration function in appropriate module
2. Return findings in standard format:
```python
{
    'type': 'category',
    'description': 'Finding description',
    'details': {'key': 'value'},
    'mitigation': 'Recommended fix'
}
```

### Modifying Risk Rules
Edit `rules/risk_rules.yaml` to customize:
- Risk scoring criteria
- MITRE ATT&CK mappings
- Severity classifications
- Mitigation recommendations

## 📝 Output Formats

### JSON Format
- Machine-readable structured data
- Integration with SIEM/SOC tools
- Automated processing and analysis
- Complete metadata and findings

### Text Format  
- Human-readable reports
- Executive summaries
- Detailed finding descriptions
- Actionable mitigation steps

## 🤝 Contributing

Contributions welcome! Focus areas:
- Additional enumeration modules
- Enhanced risk scoring logic
- New output formats
- Platform-specific improvements

## ⚖️ Legal Disclaimer

This tool is for authorized security testing and educational purposes only. Users are responsible for ensuring proper authorization before scanning any systems. The authors assume no liability for misuse of this software.

## 📄 License

Released under MIT License. See LICENSE file for details.

---

**PrivEsc-Framework v1.0** - Professional privilege escalation enumeration for security professionals.