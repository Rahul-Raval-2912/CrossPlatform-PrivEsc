"""
Windows Active Directory Privilege Escalation Module
Identifies AD-specific privilege escalation opportunities
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
    """Enumerate Active Directory privilege escalation vectors"""
    findings = []
    
    # Check if system is domain-joined
    domain_info = run_command('echo %USERDOMAIN%')
    if domain_info and domain_info != '%USERDOMAIN%' and domain_info != 'WORKGROUP':
        
        # Check for cached credentials
        cached_creds = run_command('cmdkey /list | findstr "Domain"')
        if cached_creds:
            findings.append({
                'type': 'active_directory',
                'description': 'Cached domain credentials found',
                'details': {'credentials': cached_creds, 'domain': domain_info},
                'mitigation': 'Clear cached credentials: cmdkey /delete:target'
            })
        
        # Check for Kerberos tickets
        klist_output = run_command('klist 2>nul')
        if klist_output and 'krbtgt' in klist_output:
            findings.append({
                'type': 'active_directory',
                'description': 'Active Kerberos tickets found',
                'details': {'tickets': klist_output[:200], 'domain': domain_info},
                'mitigation': 'Review Kerberos ticket usage and expiration'
            })
        
        # Check for unconstrained delegation
        delegation_check = run_command('whoami /all | findstr "SeTcbPrivilege\\|SeEnableDelegationPrivilege"')
        if delegation_check:
            findings.append({
                'type': 'active_directory',
                'description': 'Delegation privileges detected',
                'details': {'privileges': delegation_check, 'risk': 'Potential Kerberos delegation abuse'},
                'mitigation': 'Review delegation privileges necessity'
            })
    
    # Check for LAPS (Local Administrator Password Solution)
    laps_check = run_command('reg query "HKLM\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd" 2>nul')
    if not laps_check:
        findings.append({
            'type': 'active_directory',
            'description': 'LAPS not configured',
            'details': {'status': 'Not installed or configured', 'risk': 'Shared local admin passwords'},
            'mitigation': 'Implement LAPS for local administrator password management'
        })
    
    # Check for PowerShell execution policy
    ps_policy = run_command('powershell -Command "Get-ExecutionPolicy" 2>nul')
    if ps_policy and ps_policy.lower() in ['unrestricted', 'bypass']:
        findings.append({
            'type': 'active_directory',
            'description': f'PowerShell execution policy too permissive: {ps_policy}',
            'details': {'policy': ps_policy, 'risk': 'Malicious script execution possible'},
            'mitigation': 'Set PowerShell execution policy to RemoteSigned or AllSigned'
        })
    
    # Check for WinRM configuration
    winrm_config = run_command('winrm get winrm/config 2>nul')
    if winrm_config and 'AllowUnencrypted = true' in winrm_config:
        findings.append({
            'type': 'active_directory',
            'description': 'WinRM allows unencrypted communication',
            'details': {'config': 'AllowUnencrypted = true', 'risk': 'Credential interception'},
            'mitigation': 'Configure WinRM to require encryption'
        })
    
    # Check for Group Policy preferences with stored passwords
    gpp_files = run_command('dir /s /b C:\\Windows\\SYSVOL\\*Groups.xml 2>nul')
    if gpp_files:
        findings.append({
            'type': 'active_directory',
            'description': 'Group Policy Preferences files found',
            'details': {'files': gpp_files, 'risk': 'Potential stored passwords (cpassword)'},
            'mitigation': 'Review GPP files for stored credentials'
        })
    
    # Check for DCSync privileges
    dcsync_check = run_command('whoami /all | findstr "DS-Replication-Get-Changes"')
    if dcsync_check:
        findings.append({
            'type': 'active_directory',
            'description': 'DCSync privileges detected',
            'details': {'privileges': dcsync_check, 'risk': 'Can dump domain credentials'},
            'mitigation': 'Review DCSync privileges - extremely dangerous'
        })
    
    # Check for AdminSDHolder membership
    adminsd_check = run_command('net user %USERNAME% /domain 2>nul | findstr "adminCount"')
    if adminsd_check:
        findings.append({
            'type': 'active_directory',
            'description': 'User may be in AdminSDHolder protected group',
            'details': {'user': run_command('echo %USERNAME%'), 'risk': 'Privileged account'},
            'mitigation': 'Review privileged group memberships'
        })
    
    return findings