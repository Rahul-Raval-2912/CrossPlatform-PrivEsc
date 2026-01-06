"""
Linux Kernel Enumeration Module
Identifies kernel vulnerabilities and misconfigurations
"""

import subprocess
import re
from datetime import datetime

def run_command(cmd):
    """Execute command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.stdout.strip()
    except:
        return ""

def enumerate():
    """Enumerate kernel-related privilege escalation vectors"""
    findings = []
    
    # Get kernel information
    kernel_version = run_command('uname -r')
    kernel_full = run_command('uname -a')
    
    if kernel_version:
        # Parse kernel version
        version_match = re.match(r'(\d+)\.(\d+)\.(\d+)', kernel_version)
        if version_match:
            major, minor, patch = map(int, version_match.groups())
            
            # Known vulnerable kernel versions (examples)
            vulnerable_kernels = {
                'CVE-2021-4034': {'max_version': (5, 16, 0), 'description': 'PwnKit - pkexec privilege escalation'},
                'CVE-2022-0847': {'max_version': (5, 16, 11), 'description': 'Dirty Pipe - arbitrary file write'},
                'CVE-2021-3493': {'max_version': (5, 11, 22), 'description': 'OverlayFS privilege escalation'},
                'CVE-2017-16995': {'max_version': (4, 14, 0), 'description': 'BPF privilege escalation'},
                'CVE-2016-5195': {'max_version': (4, 8, 3), 'description': 'Dirty COW - race condition'}
            }
            
            current_version = (major, minor, patch)
            
            for cve, vuln_info in vulnerable_kernels.items():
                if current_version <= vuln_info['max_version']:
                    findings.append({
                        'type': 'kernel',
                        'description': f'Potentially vulnerable kernel: {cve}',
                        'details': {
                            'cve': cve,
                            'current_version': kernel_version,
                            'vulnerability': vuln_info['description'],
                            'max_vulnerable': '.'.join(map(str, vuln_info['max_version']))
                        },
                        'mitigation': 'Update kernel to latest stable version'
                    })
            
            # Check for very old kernels
            if major < 4 or (major == 4 and minor < 19):
                findings.append({
                    'type': 'kernel',
                    'description': f'Outdated kernel version: {kernel_version}',
                    'details': {'version': kernel_version, 'status': 'end-of-life'},
                    'mitigation': 'Upgrade to supported kernel version (5.4+ LTS recommended)'
                })
    
    # Check kernel modules
    loaded_modules = run_command('lsmod')
    dangerous_modules = ['usbmon', 'pcspkr', 'soundcore']
    
    for module in dangerous_modules:
        if module in loaded_modules:
            findings.append({
                'type': 'kernel',
                'description': f'Potentially unnecessary kernel module loaded: {module}',
                'details': {'module': module},
                'mitigation': f'Consider blacklisting module: echo "blacklist {module}" >> /etc/modprobe.d/blacklist.conf'
            })
    
    # Check for writable kernel modules directory
    module_dirs = ['/lib/modules', '/usr/lib/modules']
    for module_dir in module_dirs:
        if run_command(f'test -d {module_dir} && echo exists') == 'exists':
            perms = run_command(f'ls -ld {module_dir}')
            if perms and 'rw-' in perms[7:10]:  # Others writable
                findings.append({
                    'type': 'kernel',
                    'description': f'Writable kernel modules directory: {module_dir}',
                    'details': {'directory': module_dir, 'permissions': perms},
                    'mitigation': f'Fix permissions: chmod o-w {module_dir}'
                })
    
    # Check dmesg for security-relevant messages
    dmesg_output = run_command('dmesg 2>/dev/null | tail -100')
    security_keywords = ['segfault', 'oops', 'panic', 'protection fault', 'stack overflow']
    
    for keyword in security_keywords:
        if keyword.lower() in dmesg_output.lower():
            findings.append({
                'type': 'kernel',
                'description': f'Security-relevant kernel message detected: {keyword}',
                'details': {'keyword': keyword, 'source': 'dmesg'},
                'mitigation': 'Investigate kernel messages for potential security issues'
            })
    
    # Check kernel parameters
    kernel_params = run_command('cat /proc/cmdline 2>/dev/null')
    if kernel_params:
        # Check for insecure boot parameters
        insecure_params = ['init=/bin/sh', 'single', 'emergency', 'rescue']
        for param in insecure_params:
            if param in kernel_params:
                findings.append({
                    'type': 'kernel',
                    'description': f'Insecure kernel boot parameter: {param}',
                    'details': {'parameter': param, 'cmdline': kernel_params},
                    'mitigation': f'Remove {param} from kernel command line'
                })
        
        # Check for missing security features
        security_features = ['kaslr', 'smep', 'smap', 'pti']
        missing_features = []
        for feature in security_features:
            if feature not in kernel_params.lower():
                missing_features.append(feature)
        
        if missing_features:
            findings.append({
                'type': 'kernel',
                'description': f'Missing kernel security features: {", ".join(missing_features)}',
                'details': {'missing_features': missing_features, 'cmdline': kernel_params},
                'mitigation': 'Enable kernel security features in boot configuration'
            })
    
    # Check /proc/sys/kernel security settings
    kernel_settings = {
        '/proc/sys/kernel/dmesg_restrict': '1',
        '/proc/sys/kernel/kptr_restrict': '2',
        '/proc/sys/kernel/perf_event_paranoid': '3',
        '/proc/sys/kernel/yama/ptrace_scope': '1'
    }
    
    for setting_path, recommended_value in kernel_settings.items():
        current_value = run_command(f'cat {setting_path} 2>/dev/null')
        if current_value and current_value != recommended_value:
            findings.append({
                'type': 'kernel',
                'description': f'Insecure kernel setting: {setting_path}',
                'details': {
                    'setting': setting_path,
                    'current_value': current_value,
                    'recommended_value': recommended_value
                },
                'mitigation': f'Set secure value: echo {recommended_value} > {setting_path}'
            })
    
    return findings