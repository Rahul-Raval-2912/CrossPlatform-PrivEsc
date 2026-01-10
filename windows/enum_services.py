"""
Windows Services Enumeration Module - Fixed False Positives
Identifies genuine service-related privilege escalation opportunities
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

def is_system_protected_path(path):
    """Check if path is system-protected and should be ignored"""
    protected_paths = [
        'c:\\windows\\system32\\svchost.exe',
        'c:\\windows\\system32\\',
        'c:\\windows\\syswow64\\',
        'c:\\program files\\windows defender\\',
        'c:\\program files (x86)\\windows defender\\'
    ]
    
    path_lower = path.lower()
    return any(path_lower.startswith(protected) for protected in protected_paths)

def enumerate():
    """Enumerate Windows service vulnerabilities - Fixed"""
    findings = []
    
    # Get services with custom binaries only (not svchost.exe)
    services_output = run_command('wmic service get name,pathname,startname /format:csv')
    
    if services_output:
        lines = services_output.split('\n')[1:]  # Skip header
        processed_services = set()  # Avoid duplicates
        
        for line in lines:
            if line.strip() and ',' in line:
                parts = line.strip().split(',')
                if len(parts) >= 4:
                    name = parts[1].strip()
                    pathname = parts[2].strip()
                    startname = parts[3].strip()
                    
                    # Skip if already processed or empty
                    if not name or not pathname or name in processed_services:
                        continue
                    
                    processed_services.add(name)
                    
                    # Skip system services (svchost.exe)
                    if 'svchost.exe' in pathname.lower():
                        continue
                    
                    # Skip system-protected paths
                    if is_system_protected_path(pathname):
                        continue
                    
                    # Extract executable path
                    exe_path = pathname.split()[0].strip('"') if pathname.split() else pathname
                    
                    # Check for unquoted paths with spaces (real vulnerability)
                    if ' ' in pathname and not (pathname.startswith('"') and '"' in pathname[1:]):
                        # Only flag if path contains spaces and is not in system directories
                        if not is_system_protected_path(exe_path):
                            findings.append({
                                'type': 'service',
                                'description': f'Unquoted service path: {name}',
                                'details': {
                                    'service': name,
                                    'path': pathname,
                                    'vulnerability': 'Unquoted Service Path'
                                },
                                'mitigation': f'Quote the service path for {name}'
                            })
                    
                    # Check if service binary exists and is actually writable
                    if os.path.exists(exe_path):
                        try:
                            # Only check non-system files
                            if not is_system_protected_path(exe_path):
                                # Try to open file for writing (more accurate test)
                                with open(exe_path, 'r+b'):
                                    pass
                                findings.append({
                                    'type': 'service',
                                    'description': f'Writable service binary: {name}',
                                    'details': {
                                        'service': name,
                                        'binary_path': exe_path
                                    },
                                    'mitigation': f'Secure permissions on {exe_path}'
                                })
                        except (PermissionError, OSError):
                            # File is not writable - this is normal and expected
                            pass
    
    # Check for AlwaysInstallElevated (real vulnerability)
    always_install_hkcu = run_command('reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul')
    always_install_hklm = run_command('reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul')
    
    if 'AlwaysInstallElevated' in always_install_hkcu and 'AlwaysInstallElevated' in always_install_hklm:
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
    
    # Check for services running from writable directories
    writable_service_dirs = ['C:\\temp', 'C:\\tmp', 'C:\\Users\\Public']
    
    for line in services_output.split('\n')[1:]:
        if line.strip() and ',' in line:
            parts = line.strip().split(',')
            if len(parts) >= 4:
                name = parts[1].strip()
                pathname = parts[2].strip()
                
                if name and pathname:
                    for writable_dir in writable_service_dirs:
                        if pathname.lower().startswith(writable_dir.lower()):
                            findings.append({
                                'type': 'service',
                                'description': f'Service in writable directory: {name}',
                                'details': {
                                    'service': name,
                                    'path': pathname,
                                    'directory': writable_dir
                                },
                                'mitigation': f'Move service binary to secure location'
                            })
                            break
    
    return findings