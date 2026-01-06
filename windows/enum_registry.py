"""
Windows Registry Enumeration Module
Identifies registry-based privilege escalation opportunities
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
    """Enumerate Windows registry vulnerabilities"""
    findings = []
    
    # Check AutoRun entries
    autorun_keys = [
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
        'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
    ]
    
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
                        
                        # Check for writable paths
                        if 'C:\\temp' in value.lower() or 'C:\\tmp' in value.lower():
                            findings.append({
                                'type': 'registry',
                                'description': f'AutoRun entry in writable location: {name}',
                                'details': {
                                    'key': key,
                                    'name': name,
                                    'value': value
                                },
                                'mitigation': f'Remove or secure AutoRun entry: {name}'
                            })
                        
                        # Check for missing quotes in paths with spaces
                        if ' ' in value and not (value.startswith('"') and '"' in value[1:]):
                            findings.append({
                                'type': 'registry',
                                'description': f'Unquoted AutoRun path: {name}',
                                'details': {
                                    'key': key,
                                    'name': name,
                                    'value': value
                                },
                                'mitigation': f'Quote the path in AutoRun entry: {name}'
                            })
    
    # Check for weak registry permissions
    sensitive_keys = [
        'HKLM\\SYSTEM\\CurrentControlSet\\Services',
        'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies'
    ]
    
    for key in sensitive_keys:
        # Check if current user has write access (simplified check)
        reg_perms = run_command(f'reg query "{key}" /s 2>nul | findstr /i "error"')
        if not reg_perms:  # No error means we have some access
            findings.append({
                'type': 'registry',
                'description': f'Potential access to sensitive registry key: {key}',
                'details': {'key': key},
                'mitigation': f'Verify and restrict permissions on {key}'
            })
    
    # Check for stored credentials in registry
    credential_keys = [
        'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
        'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU',
        'HKLM\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities'
    ]
    
    for key in credential_keys:
        cred_output = run_command(f'reg query "{key}" 2>nul')
        if cred_output:
            # Look for password-related entries
            password_indicators = ['password', 'passwd', 'pwd', 'credential', 'secret']
            for indicator in password_indicators:
                if indicator.lower() in cred_output.lower():
                    findings.append({
                        'type': 'registry',
                        'description': f'Potential credentials in registry: {key}',
                        'details': {
                            'key': key,
                            'indicator': indicator
                        },
                        'mitigation': f'Remove stored credentials from {key}'
                    })
    
    # Check UAC settings
    uac_settings = [
        ('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA', '1'),
        ('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin', '2'),
        ('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop', '1')
    ]
    
    for setting_key, expected_value in uac_settings:
        setting_output = run_command(f'reg query "{setting_key}" 2>nul')
        if setting_output:
            value_match = re.search(r'REG_DWORD\s+0x(\w+)', setting_output)
            if value_match:
                current_value = str(int(value_match.group(1), 16))
                if current_value != expected_value:
                    findings.append({
                        'type': 'registry',
                        'description': f'Weak UAC setting: {setting_key.split("\\")[-1]}',
                        'details': {
                            'key': setting_key,
                            'current_value': current_value,
                            'expected_value': expected_value
                        },
                        'mitigation': f'Set secure UAC value: reg add "{setting_key}" /v {setting_key.split("\\")[-1]} /t REG_DWORD /d {expected_value} /f'
                    })
    
    # Check for hijackable DLL paths in registry
    dll_hijack_keys = [
        'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs',
        'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\SafeDllSearchMode'
    ]
    
    for key in dll_hijack_keys:
        dll_output = run_command(f'reg query "{key}" 2>nul')
        if dll_output and 'SafeDllSearchMode' in key:
            # Check if SafeDllSearchMode is disabled (0)
            if 'REG_DWORD    0x0' in dll_output:
                findings.append({
                    'type': 'registry',
                    'description': 'SafeDllSearchMode disabled - DLL hijacking possible',
                    'details': {
                        'key': key,
                        'value': '0 (disabled)'
                    },
                    'mitigation': 'Enable SafeDllSearchMode: reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" /v SafeDllSearchMode /t REG_DWORD /d 1 /f'
                })
    
    # Check Windows Defender exclusions
    defender_exclusions = run_command('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths" 2>nul')
    if defender_exclusions:
        lines = defender_exclusions.split('\n')[2:]  # Skip header
        for line in lines:
            if line.strip() and 'REG_DWORD' in line:
                path = line.strip().split('    ')[0]
                # Check for overly broad exclusions
                broad_paths = ['C:\\', 'C:\\Windows', 'C:\\Program Files']
                if any(broad_path.lower() in path.lower() for broad_path in broad_paths):
                    findings.append({
                        'type': 'registry',
                        'description': f'Overly broad Windows Defender exclusion: {path}',
                        'details': {
                            'exclusion_path': path,
                            'key': 'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths'
                        },
                        'mitigation': f'Remove or narrow Defender exclusion: {path}'
                    })
    
    return findings