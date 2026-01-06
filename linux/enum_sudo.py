"""
Linux Sudo Enumeration Module
Identifies sudo misconfigurations and privilege escalation paths
"""

import subprocess
import os

def run_command(cmd):
    """Execute command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.stdout.strip()
    except:
        return ""

def enumerate():
    """Enumerate sudo-related privilege escalation vectors"""
    findings = []
    
    # Check sudo -l output
    sudo_list = run_command('sudo -l 2>/dev/null')
    if sudo_list:
        lines = sudo_list.split('\n')
        for line in lines:
            # Check for NOPASSWD entries
            if 'NOPASSWD' in line:
                findings.append({
                    'type': 'sudo',
                    'description': 'NOPASSWD sudo rule found',
                    'details': {'rule': line.strip()},
                    'mitigation': 'Review and restrict NOPASSWD sudo rules'
                })
            
            # Check for dangerous binaries with sudo access
            dangerous_bins = ['vim', 'nano', 'less', 'more', 'find', 'awk', 'python', 'perl', 'ruby', 'bash', 'sh']
            for binary in dangerous_bins:
                if binary in line and ('ALL' in line or f'/{binary}' in line):
                    findings.append({
                        'type': 'sudo',
                        'description': f'Dangerous sudo binary access: {binary}',
                        'details': {'binary': binary, 'rule': line.strip()},
                        'mitigation': f'Restrict sudo access to {binary} or use specific parameters'
                    })
    
    # Check sudoers file permissions
    sudoers_files = ['/etc/sudoers', '/etc/sudoers.d/*']
    for sudoers_pattern in sudoers_files:
        sudoers_list = run_command(f'find {sudoers_pattern} -type f 2>/dev/null')
        for sudoers_file in sudoers_list.split('\n'):
            if sudoers_file:
                perms = run_command(f'ls -la "{sudoers_file}"')
                if perms:
                    # Check if writable by non-root
                    if 'rw-' in perms[4:7] or 'rw-' in perms[7:10]:
                        findings.append({
                            'type': 'sudo',
                            'description': f'Writable sudoers file: {sudoers_file}',
                            'details': {'file': sudoers_file, 'permissions': perms},
                            'mitigation': f'Fix permissions: chmod 440 {sudoers_file}'
                        })
    
    # Check for sudo version vulnerabilities
    sudo_version = run_command('sudo --version 2>/dev/null | head -1')
    if sudo_version:
        # Extract version number
        import re
        version_match = re.search(r'version (\d+\.\d+\.\d+)', sudo_version)
        if version_match:
            version = version_match.group(1)
            major, minor, patch = map(int, version.split('.'))
            
            # Check for known vulnerable versions (example: CVE-2021-3156)
            if major == 1 and minor < 9 or (minor == 9 and patch < 5):
                findings.append({
                    'type': 'sudo',
                    'description': f'Potentially vulnerable sudo version: {version}',
                    'details': {'version': version, 'cve': 'CVE-2021-3156'},
                    'mitigation': 'Update sudo to latest version'
                })
    
    # Check for sudo token hijacking opportunities
    sudo_tokens = run_command('find /var/lib/sudo -name "*" 2>/dev/null')
    if sudo_tokens:
        for token_file in sudo_tokens.split('\n'):
            if token_file:
                perms = run_command(f'ls -la "{token_file}"')
                if perms and ('r--' in perms[4:7] or 'r--' in perms[7:10]):
                    findings.append({
                        'type': 'sudo',
                        'description': f'Readable sudo token file: {token_file}',
                        'details': {'file': token_file, 'permissions': perms},
                        'mitigation': 'Secure sudo token directory permissions'
                    })
    
    return findings