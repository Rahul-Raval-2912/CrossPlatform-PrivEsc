"""
Windows Token Enumeration Module - Focused on Real Vulnerabilities
Identifies genuine token-based privilege escalation opportunities
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
    """Enumerate Windows token vulnerabilities - Focused"""
    findings = []
    
    # Check for dangerous privileges that are actually enabled
    whoami_priv = run_command('whoami /priv')
    if whoami_priv:
        dangerous_enabled_privileges = {
            'SeDebugPrivilege': 'Debug programs - can access any process',
            'SeBackupPrivilege': 'Backup files and directories - can read any file',
            'SeRestorePrivilege': 'Restore files and directories - can write any file',
            'SeTakeOwnershipPrivilege': 'Take ownership of files - can own any file',
            'SeLoadDriverPrivilege': 'Load device drivers - can load kernel drivers',
            'SeTcbPrivilege': 'Act as part of OS - highest privilege',
            'SeCreateTokenPrivilege': 'Create access tokens - impersonation',
            'SeAssignPrimaryTokenPrivilege': 'Replace process token - impersonation',
            'SeImpersonatePrivilege': 'Impersonate client - token manipulation'
        }
        
        for privilege, description in dangerous_enabled_privileges.items():
            if privilege in whoami_priv:
                # Only flag if privilege is ENABLED
                privilege_lines = [line for line in whoami_priv.split('\n') if privilege in line]
                if privilege_lines and 'Enabled' in privilege_lines[0]:
                    findings.append({
                        'type': 'token',
                        'description': f'Dangerous privilege enabled: {privilege}',
                        'details': {
                            'privilege': privilege,
                            'status': 'Enabled',
                            'description': description
                        },
                        'mitigation': f'Review necessity of {privilege} for current user'
                    })
    
    # Check for high-privilege group memberships
    whoami_groups = run_command('whoami /groups')
    if whoami_groups:
        high_privilege_groups = [
            'BUILTIN\\Administrators',
            'BUILTIN\\Backup Operators',
            'BUILTIN\\Server Operators'
        ]
        
        for group in high_privilege_groups:
            if group in whoami_groups and 'Enabled group' in whoami_groups:
                findings.append({
                    'type': 'token',
                    'description': f'User in high-privilege group: {group}',
                    'details': {'group': group},
                    'mitigation': f'Review membership in {group}'
                })
    
    # Check for stored credentials
    cmdkey_output = run_command('cmdkey /list')
    if cmdkey_output and 'Target:' in cmdkey_output and 'TERMSRV' not in cmdkey_output:
        # Only flag non-RDP credentials
        findings.append({
            'type': 'token',
            'description': 'Stored credentials found in Credential Manager',
            'details': {'source': 'cmdkey /list'},
            'mitigation': 'Review and remove unnecessary stored credentials'
        })
    
    # Check if WDigest is enabled (stores plaintext passwords)
    wdigest_setting = run_command('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" /v UseLogonCredential 2>nul')
    if wdigest_setting and 'REG_DWORD    0x1' in wdigest_setting:
        findings.append({
            'type': 'token',
            'description': 'WDigest plaintext password storage enabled',
            'details': {
                'key': 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest',
                'setting': 'UseLogonCredential = 1'
            },
            'mitigation': 'Disable WDigest: reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f'
        })
    
    # Check for LSA protection status
    lsa_protection = run_command('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v RunAsPPL 2>nul')
    if not lsa_protection or 'REG_DWORD    0x0' in lsa_protection:
        findings.append({
            'type': 'token',
            'description': 'LSA protection not enabled',
            'details': {
                'setting': 'RunAsPPL not set or disabled',
                'impact': 'LSASS process not protected from memory dumps'
            },
            'mitigation': 'Enable LSA protection: reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f'
        })
    
    return findings