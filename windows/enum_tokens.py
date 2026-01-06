"""
Windows Token Enumeration Module
Identifies token-based privilege escalation opportunities
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
    """Enumerate Windows token vulnerabilities"""
    findings = []
    
    # Check current user privileges
    whoami_priv = run_command('whoami /priv')
    if whoami_priv:
        dangerous_privileges = {
            'SeDebugPrivilege': 'Debug programs - can access any process',
            'SeBackupPrivilege': 'Backup files and directories - can read any file',
            'SeRestorePrivilege': 'Restore files and directories - can write any file',
            'SeTakeOwnershipPrivilege': 'Take ownership of files - can own any file',
            'SeLoadDriverPrivilege': 'Load device drivers - can load kernel drivers',
            'SeSystemtimePrivilege': 'Change system time - potential for attacks',
            'SeShutdownPrivilege': 'Shutdown system - denial of service',
            'SeRemoteShutdownPrivilege': 'Remote shutdown - denial of service',
            'SeTcbPrivilege': 'Act as part of OS - highest privilege',
            'SeCreateTokenPrivilege': 'Create access tokens - impersonation',
            'SeAssignPrimaryTokenPrivilege': 'Replace process token - impersonation',
            'SeIncreaseQuotaPrivilege': 'Increase memory quota - resource manipulation',
            'SeImpersonatePrivilege': 'Impersonate client - token manipulation',
            'SeCreateGlobalPrivilege': 'Create global objects - namespace manipulation'
        }
        
        for privilege, description in dangerous_privileges.items():
            if privilege in whoami_priv:
                # Check if privilege is enabled
                privilege_line = [line for line in whoami_priv.split('\n') if privilege in line]
                if privilege_line:
                    status = 'Enabled' if 'Enabled' in privilege_line[0] else 'Disabled'
                    findings.append({
                        'type': 'token',
                        'description': f'Dangerous privilege found: {privilege}',
                        'details': {
                            'privilege': privilege,
                            'status': status,
                            'description': description
                        },
                        'mitigation': f'Review necessity of {privilege} for current user'
                    })
    
    # Check for impersonation opportunities
    whoami_groups = run_command('whoami /groups')
    if whoami_groups:
        high_privilege_groups = [
            'BUILTIN\\Administrators',
            'BUILTIN\\Backup Operators',
            'BUILTIN\\Server Operators',
            'BUILTIN\\Account Operators',
            'BUILTIN\\Print Operators'
        ]
        
        for group in high_privilege_groups:
            if group in whoami_groups:
                findings.append({
                    'type': 'token',
                    'description': f'User in high-privilege group: {group}',
                    'details': {'group': group},
                    'mitigation': f'Review membership in {group}'
                })
    
    # Check for token manipulation opportunities via services
    services_tokens = run_command('sc query type= service state= all | findstr "SERVICE_NAME"')
    if services_tokens:
        service_names = re.findall(r'SERVICE_NAME: (.+)', services_tokens)
        
        for service_name in service_names[:10]:  # Limit to first 10 for performance
            service_name = service_name.strip()
            
            # Check service account
            service_config = run_command(f'sc qc "{service_name}"')
            if service_config:
                start_name_match = re.search(r'START_NAME\s*:\s*(.+)', service_config)
                if start_name_match:
                    start_name = start_name_match.group(1).strip()
                    
                    # Check for services running as SYSTEM that might be exploitable
                    if 'LocalSystem' in start_name:
                        # Check if service binary is writable
                        binary_path_match = re.search(r'BINARY_PATH_NAME\s*:\s*(.+)', service_config)
                        if binary_path_match:
                            binary_path = binary_path_match.group(1).strip().strip('"')
                            
                            # Simple check for writable service binary
                            try:
                                import os
                                if os.path.exists(binary_path) and os.access(binary_path, os.W_OK):
                                    findings.append({
                                        'type': 'token',
                                        'description': f'Writable SYSTEM service binary: {service_name}',
                                        'details': {
                                            'service': service_name,
                                            'binary': binary_path,
                                            'account': start_name
                                        },
                                        'mitigation': f'Secure permissions on {binary_path}'
                                    })
                            except:
                                pass
    
    # Check for stored credentials that could be used for token manipulation
    cmdkey_output = run_command('cmdkey /list')
    if cmdkey_output and 'Target:' in cmdkey_output:
        findings.append({
            'type': 'token',
            'description': 'Stored credentials found in Credential Manager',
            'details': {'source': 'cmdkey /list'},
            'mitigation': 'Review and remove unnecessary stored credentials'
        })
    
    # Check for runas saved credentials
    runas_output = run_command('runas /savecred /user:administrator cmd 2>&1')
    if 'saved' in runas_output.lower():
        findings.append({
            'type': 'token',
            'description': 'Saved runas credentials detected',
            'details': {'command': 'runas /savecred'},
            'mitigation': 'Clear saved runas credentials'
        })
    
    # Check for token-related registry entries
    token_reg_keys = [
        'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0',
        'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest'
    ]
    
    for key in token_reg_keys:
        reg_output = run_command(f'reg query "{key}" 2>nul')
        if reg_output:
            if 'WDigest' in key and 'UseLogonCredential' in reg_output:
                # Check if WDigest is enabled (stores plaintext passwords)
                if 'REG_DWORD    0x1' in reg_output:
                    findings.append({
                        'type': 'token',
                        'description': 'WDigest plaintext password storage enabled',
                        'details': {
                            'key': key,
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