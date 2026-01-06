"""
Windows Services Enumeration Module
Identifies service-related privilege escalation opportunities
"""

import subprocess
import os
import re

def run_command(cmd):
    """Execute command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.stdout.strip()
    except:
        return ""

def enumerate():
    """Enumerate Windows service vulnerabilities"""
    findings = []
    
    # Get all services
    services_output = run_command('sc query type= service state= all')
    
    if services_output:
        # Parse service names
        service_names = re.findall(r'SERVICE_NAME: (.+)', services_output)
        
        for service_name in service_names:
            service_name = service_name.strip()
            
            # Get service configuration
            service_config = run_command(f'sc qc "{service_name}"')
            
            if service_config:
                # Check for unquoted service paths
                binary_path_match = re.search(r'BINARY_PATH_NAME\s*:\s*(.+)', service_config)
                if binary_path_match:
                    binary_path = binary_path_match.group(1).strip()
                    
                    # Check for unquoted paths with spaces
                    if ' ' in binary_path and not (binary_path.startswith('"') and binary_path.endswith('"')):
                        findings.append({
                            'type': 'service',
                            'description': f'Unquoted service path: {service_name}',
                            'details': {
                                'service': service_name,
                                'path': binary_path,
                                'vulnerability': 'Unquoted Service Path'
                            },
                            'mitigation': f'Quote the service path for {service_name}'
                        })
                    
                    # Check if service binary is writable
                    # Extract actual executable path
                    exe_path = binary_path.split()[0].strip('"')
                    if os.path.exists(exe_path):
                        try:
                            # Check if current user can write to the file
                            if os.access(exe_path, os.W_OK):
                                findings.append({
                                    'type': 'service',
                                    'description': f'Writable service binary: {service_name}',
                                    'details': {
                                        'service': service_name,
                                        'binary_path': exe_path
                                    },
                                    'mitigation': f'Restrict write permissions on {exe_path}'
                                })
                        except:
                            pass
                
                # Check service permissions
                service_perms = run_command(f'sc sdshow "{service_name}"')
                if service_perms and 'SDDL' not in service_perms:
                    # Look for weak service permissions (simplified check)
                    if 'Everyone' in service_perms or 'Users' in service_perms:
                        findings.append({
                            'type': 'service',
                            'description': f'Weak service permissions: {service_name}',
                            'details': {
                                'service': service_name,
                                'permissions': service_perms
                            },
                            'mitigation': f'Restrict service permissions for {service_name}'
                        })
    
    # Check for services running as SYSTEM with weak configurations
    wmic_services = run_command('wmic service get name,startname,pathname')
    if wmic_services:
        lines = wmic_services.split('\n')[1:]  # Skip header
        for line in lines:
            if line.strip():
                parts = line.strip().split()
                if len(parts) >= 3:
                    name = parts[0]
                    pathname = ' '.join(parts[1:-1]) if len(parts) > 3 else parts[1]
                    startname = parts[-1]
                    
                    # Check for services running as SYSTEM
                    if 'LocalSystem' in startname or 'SYSTEM' in startname:
                        # Check if pathname is in a writable directory
                        writable_dirs = ['C:\\temp', 'C:\\tmp', 'C:\\Users\\Public']
                        for writable_dir in writable_dirs:
                            if pathname.lower().startswith(writable_dir.lower()):
                                findings.append({
                                    'type': 'service',
                                    'description': f'SYSTEM service in writable directory: {name}',
                                    'details': {
                                        'service': name,
                                        'path': pathname,
                                        'account': startname
                                    },
                                    'mitigation': f'Move service binary to secure location'
                                })
    
    # Check for AlwaysInstallElevated
    always_install_hkcu = run_command('reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul')
    always_install_hklm = run_command('reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul')
    
    if 'AlwaysInstallElevated' in always_install_hkcu and 'AlwaysInstallElevated' in always_install_hklm:
        # Check if both are set to 1
        hkcu_value = re.search(r'AlwaysInstallElevated\s+REG_DWORD\s+0x1', always_install_hkcu)
        hklm_value = re.search(r'AlwaysInstallElevated\s+REG_DWORD\s+0x1', always_install_hklm)
        
        if hkcu_value and hklm_value:
            findings.append({
                'type': 'service',
                'description': 'AlwaysInstallElevated enabled',
                'details': {
                    'vulnerability': 'MSI packages run with SYSTEM privileges',
                    'hkcu': 'Enabled',
                    'hklm': 'Enabled'
                },
                'mitigation': 'Disable AlwaysInstallElevated in both HKCU and HKLM'
            })
    
    # Check for weak service ACLs using accesschk (if available)
    accesschk_output = run_command('accesschk.exe -uwcqv "Authenticated Users" * 2>nul')
    if accesschk_output and 'SERVICE_CHANGE_CONFIG' in accesschk_output:
        services_with_weak_acl = re.findall(r'(\w+)\s+SERVICE_CHANGE_CONFIG', accesschk_output)
        for service in services_with_weak_acl:
            findings.append({
                'type': 'service',
                'description': f'Service with weak ACL: {service}',
                'details': {
                    'service': service,
                    'permission': 'SERVICE_CHANGE_CONFIG',
                    'group': 'Authenticated Users'
                },
                'mitigation': f'Restrict service permissions for {service}'
            })
    
    return findings