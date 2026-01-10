"""
Advanced Container Escape Detection Module
Detects Docker, LXC, and container privilege escalation opportunities
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
    """Enumerate container escape opportunities"""
    findings = []
    
    # Check if running in Docker
    if os.path.exists('/.dockerenv'):
        findings.append({
            'type': 'container',
            'description': 'Running inside Docker container',
            'details': {'container_type': 'Docker', 'escape_potential': 'High'},
            'mitigation': 'Review container security configuration'
        })
        
        # Check for privileged container
        cap_output = run_command('capsh --print 2>/dev/null')
        if 'cap_sys_admin' in cap_output:
            findings.append({
                'type': 'container',
                'description': 'Privileged Docker container detected',
                'details': {'capability': 'CAP_SYS_ADMIN', 'risk': 'Container escape possible'},
                'mitigation': 'Remove privileged mode and unnecessary capabilities'
            })
    
    # Check Docker socket access
    docker_sock = '/var/run/docker.sock'
    if os.path.exists(docker_sock):
        try:
            sock_perms = run_command(f'ls -la {docker_sock}')
            if 'rw-' in sock_perms[4:7] or 'rw-' in sock_perms[7:10]:
                findings.append({
                    'type': 'container',
                    'description': 'Docker socket accessible - container escape possible',
                    'details': {'socket': docker_sock, 'permissions': sock_perms},
                    'mitigation': 'Restrict Docker socket permissions'
                })
        except:
            pass
    
    # Check for Docker group membership
    groups_output = run_command('groups')
    if 'docker' in groups_output:
        findings.append({
            'type': 'container',
            'description': 'User in docker group - equivalent to root access',
            'details': {'group': 'docker', 'risk': 'Full system compromise possible'},
            'mitigation': 'Remove user from docker group or use rootless Docker'
        })
    
    # Check for LXD/LXC containers
    if os.path.exists('/var/lib/lxd') or run_command('which lxc 2>/dev/null'):
        lxd_group = run_command('groups | grep lxd')
        if lxd_group:
            findings.append({
                'type': 'container',
                'description': 'User in lxd group - container escape possible',
                'details': {'group': 'lxd', 'container_type': 'LXD'},
                'mitigation': 'Remove user from lxd group'
            })
    
    # Check for container runtime vulnerabilities
    runc_version = run_command('runc --version 2>/dev/null')
    if runc_version and 'version' in runc_version:
        # Check for known vulnerable runc versions
        if '1.0-rc' in runc_version or '1.0.0-rc' in runc_version:
            findings.append({
                'type': 'container',
                'description': 'Vulnerable runc version detected',
                'details': {'version': runc_version, 'cve': 'CVE-2019-5736'},
                'mitigation': 'Update runc to latest stable version'
            })
    
    return findings