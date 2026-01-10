"""
Windows Registry Enumeration Module - Reduced False Positives
Identifies genuine registry-based privilege escalation opportunities
"""

import subprocess
import re

def run_command(cmd):
    """Execute command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.stdout.strip()
    except:
        return ""

def enumerate():
    """Enumerate Windows registry vulnerabilities - Fixed"""
    findings = []
    
    # Check AutoRun entries for suspicious paths only
    autorun_keys = [
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
    ]
    
    suspicious_paths = ['temp', 'tmp', 'downloads', 'desktop', 'public']
    
    for key in autorun_keys:
        autorun_output = run_command(f'reg query "{key}" 2>nul')
        if autorun_output:
            lines = autorun_output.split('\n')[2:]  # Skip header lines
            for line in lines:
                if line.strip() and 'REG_' in line:
                    parts = line.strip().split('    ')
                    if len(parts) >= 3:
                        name = parts[0]
                        value = parts[2]
                        
                        # Only flag suspicious locations
                        if any(susp_path in value.lower() for susp_path in suspicious_paths):
                            findings.append({
                                'type': 'registry',
                                'description': f'Suspicious AutoRun entry: {name}',
                                'details': {
                                    'key': key,
                                    'name': name,
                                    'value': value
                                },
                                'mitigation': f'Review AutoRun entry: {name}'
                            })
    
    # Check for stored credentials in specific locations
    credential_locations = [
        ('HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'DefaultPassword'),
        ('HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU', 'password'),
    ]
    
    for key, search_term in credential_locations:
        cred_output = run_command(f'reg query "{key}" 2>nul')
        if cred_output and search_term.lower() in cred_output.lower():
            findings.append({
                'type': 'registry',
                'description': f'Potential stored credentials in: {key}',
                'details': {
                    'key': key,
                    'indicator': search_term
                },
                'mitigation': f'Remove stored credentials from {key}'
            })
    
    # Check UAC settings - only flag if actually disabled
    uac_enabled = run_command('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA 2>nul')
    if uac_enabled and 'REG_DWORD    0x0' in uac_enabled:
        findings.append({
            'type': 'registry',
            'description': 'UAC completely disabled',
            'details': {
                'key': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA',
                'value': '0 (disabled)'
            },
            'mitigation': 'Enable UAC: reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA /t REG_DWORD /d 1 /f'
        })
    
    # Check for overly broad Windows Defender exclusions
    defender_exclusions = run_command('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths" 2>nul')
    if defender_exclusions:
        broad_exclusions = ['C:\\', 'C:\\Windows', 'C:\\Program Files']
        lines = defender_exclusions.split('\n')[2:]  # Skip header
        for line in lines:
            if line.strip() and 'REG_DWORD' in line:
                path = line.strip().split('    ')[0]
                if any(broad_path in path for broad_path in broad_exclusions):
                    findings.append({
                        'type': 'registry',
                        'description': f'Overly broad Defender exclusion: {path}',
                        'details': {
                            'exclusion_path': path,
                            'key': 'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths'
                        },
                        'mitigation': f'Remove or narrow Defender exclusion: {path}'
                    })
    
    return findings