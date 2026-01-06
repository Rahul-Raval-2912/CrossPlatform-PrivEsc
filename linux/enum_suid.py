"""
Linux SUID/SGID Enumeration Module
Deep analysis of SUID/SGID binaries and capabilities
"""

import subprocess
import os
from pathlib import Path

def run_command(cmd):
    """Execute command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.stdout.strip()
    except:
        return ""

def enumerate():
    """Enumerate SUID/SGID binaries and capabilities"""
    findings = []
    
    # GTFOBins dangerous binaries
    gtfo_bins = {
        'awk': 'awk \'BEGIN {system("/bin/sh")}\'',
        'find': 'find . -exec /bin/sh \\; -quit',
        'vim': 'vim -c \':!/bin/sh\'',
        'nano': 'nano then ^R^X reset; sh 1>&0 2>&0',
        'less': 'less /etc/profile then !/bin/sh',
        'more': 'more /etc/profile then !/bin/sh',
        'perl': 'perl -e \'exec "/bin/sh";\'',
        'python': 'python -c \'import os; os.system("/bin/sh")\'',
        'ruby': 'ruby -e \'exec "/bin/sh"\'',
        'tar': 'tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh',
        'zip': 'TF=$(mktemp -u); zip $TF /etc/hosts -T -TT \'sh #\'',
        'bash': 'bash -p',
        'sh': 'sh -p',
        'cp': 'cp /bin/sh /tmp/sh; chmod +s /tmp/sh; /tmp/sh -p'
    }
    
    # Find SUID binaries
    suid_files = run_command('find / -type f -perm -4000 2>/dev/null')
    for suid_file in suid_files.split('\n'):
        if suid_file:
            binary_name = os.path.basename(suid_file)
            
            # Check if it's a GTFOBins binary
            if binary_name in gtfo_bins:
                findings.append({
                    'type': 'suid',
                    'description': f'Dangerous SUID binary (GTFOBins): {binary_name}',
                    'details': {
                        'path': suid_file,
                        'binary': binary_name,
                        'exploit': gtfo_bins[binary_name],
                        'gtfobins': True
                    },
                    'mitigation': f'Remove SUID bit: chmod u-s {suid_file}'
                })
            else:
                # Check if binary is writable
                perms = run_command(f'ls -la "{suid_file}"')
                if perms and ('rw-' in perms[4:7] or 'rw-' in perms[7:10]):
                    findings.append({
                        'type': 'suid',
                        'description': f'Writable SUID binary: {binary_name}',
                        'details': {'path': suid_file, 'permissions': perms},
                        'mitigation': f'Fix permissions and remove SUID: chmod 755 {suid_file}'
                    })
                else:
                    findings.append({
                        'type': 'suid',
                        'description': f'SUID binary found: {binary_name}',
                        'details': {'path': suid_file, 'binary': binary_name},
                        'mitigation': f'Review necessity of SUID bit on {suid_file}'
                    })
    
    # Find SGID binaries
    sgid_files = run_command('find / -type f -perm -2000 2>/dev/null')
    for sgid_file in sgid_files.split('\n'):
        if sgid_file:
            binary_name = os.path.basename(sgid_file)
            findings.append({
                'type': 'suid',
                'description': f'SGID binary found: {binary_name}',
                'details': {'path': sgid_file, 'binary': binary_name, 'type': 'sgid'},
                'mitigation': f'Review necessity of SGID bit on {sgid_file}'
            })
    
    # Check file capabilities
    cap_files = run_command('getcap -r / 2>/dev/null')
    dangerous_caps = {
        'cap_setuid': 'Can set UID - potential privilege escalation',
        'cap_setgid': 'Can set GID - potential privilege escalation',
        'cap_dac_override': 'Can bypass file permissions',
        'cap_sys_admin': 'Administrative capabilities - high risk',
        'cap_net_admin': 'Network administration capabilities',
        'cap_sys_ptrace': 'Can trace processes - potential information disclosure'
    }
    
    for line in cap_files.split('\n'):
        if line and '=' in line:
            file_path, caps = line.split(' = ', 1)
            for cap_name, description in dangerous_caps.items():
                if cap_name in caps:
                    findings.append({
                        'type': 'suid',
                        'description': f'Dangerous file capability: {cap_name}',
                        'details': {
                            'path': file_path,
                            'capability': cap_name,
                            'description': description,
                            'full_caps': caps
                        },
                        'mitigation': f'Remove capability: setcap -r {file_path}'
                    })
    
    # Check for custom SUID binaries in unusual locations
    unusual_locations = ['/tmp', '/var/tmp', '/dev/shm', '/home']
    for location in unusual_locations:
        if os.path.exists(location):
            custom_suid = run_command(f'find {location} -type f -perm -4000 2>/dev/null')
            for custom_file in custom_suid.split('\n'):
                if custom_file:
                    findings.append({
                        'type': 'suid',
                        'description': f'Custom SUID binary in unusual location: {custom_file}',
                        'details': {'path': custom_file, 'location': location},
                        'mitigation': f'Investigate and remove: rm {custom_file}'
                    })
    
    return findings