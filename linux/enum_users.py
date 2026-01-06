"""
Linux User Enumeration Module
Enumerates users and identifies privilege escalation opportunities
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
    """Enumerate user-related privilege escalation vectors"""
    findings = []
    
    # Check /etc/passwd for unusual entries
    try:
        passwd_content = run_command('cat /etc/passwd')
        for line in passwd_content.split('\n'):
            if line and ':' in line:
                parts = line.split(':')
                if len(parts) >= 7:
                    username, _, uid, gid, _, home_dir, shell = parts[:7]
                    
                    # Check for UID 0 (root equivalent)
                    if uid == '0' and username != 'root':
                        findings.append({
                            'type': 'user_enum',
                            'description': f'Non-root user with UID 0: {username}',
                            'details': {'user': username, 'uid': uid, 'shell': shell},
                            'mitigation': f'Review user {username} with root privileges'
                        })
                    
                    # Check for writable home directories
                    if os.path.exists(home_dir):
                        perms = run_command(f'ls -ld "{home_dir}"')
                        if perms and 'rwx' in perms[7:10]:  # Others writable
                            findings.append({
                                'type': 'user_enum',
                                'description': f'World-writable home directory: {home_dir}',
                                'details': {'user': username, 'home': home_dir, 'permissions': perms},
                                'mitigation': f'Fix permissions: chmod o-w {home_dir}'
                            })
    except Exception as e:
        pass
    
    # Check for users in privileged groups
    privileged_groups = ['sudo', 'wheel', 'admin', 'docker', 'lxd']
    for group in privileged_groups:
        try:
            group_info = run_command(f'getent group {group}')
            if group_info and ':' in group_info:
                parts = group_info.split(':')
                if len(parts) >= 4 and parts[3]:
                    users = parts[3].split(',')
                    for user in users:
                        if user.strip():
                            findings.append({
                                'type': 'user_enum',
                                'description': f'User in privileged group {group}: {user.strip()}',
                                'details': {'user': user.strip(), 'group': group},
                                'mitigation': f'Review {user.strip()} membership in {group} group'
                            })
        except:
            pass
    
    # Check SSH authorized_keys
    ssh_dirs = ['/root/.ssh', '/home/*/.ssh']
    for ssh_pattern in ssh_dirs:
        auth_keys = run_command(f'find {ssh_pattern} -name "authorized_keys" 2>/dev/null')
        for key_file in auth_keys.split('\n'):
            if key_file:
                perms = run_command(f'ls -la "{key_file}"')
                if perms and ('rw-' in perms[4:7] or 'rw-' in perms[7:10]):
                    findings.append({
                        'type': 'user_enum',
                        'description': f'Weak permissions on SSH authorized_keys: {key_file}',
                        'details': {'file': key_file, 'permissions': perms},
                        'mitigation': f'Fix permissions: chmod 600 {key_file}'
                    })
    
    return findings