"""
Linux Cron and Systemd Timer Enumeration Module
Analyzes scheduled tasks for privilege escalation opportunities
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
    """Enumerate cron jobs and systemd timers"""
    findings = []
    
    # System cron directories
    cron_dirs = [
        '/etc/cron.d',
        '/etc/cron.daily', 
        '/etc/cron.hourly',
        '/etc/cron.monthly',
        '/etc/cron.weekly',
        '/var/spool/cron/crontabs'
    ]
    
    # Check system cron directories
    for cron_dir in cron_dirs:
        if os.path.exists(cron_dir):
            # Find writable cron files
            writable_crons = run_command(f'find {cron_dir} -type f -perm -002 2>/dev/null')
            for cron_file in writable_crons.split('\n'):
                if cron_file:
                    findings.append({
                        'type': 'cron',
                        'description': f'World-writable cron file: {cron_file}',
                        'details': {'file': cron_file, 'directory': cron_dir},
                        'mitigation': f'Fix permissions: chmod 644 {cron_file}'
                    })
            
            # Check cron file contents for writable scripts
            cron_files = run_command(f'find {cron_dir} -type f 2>/dev/null')
            for cron_file in cron_files.split('\n'):
                if cron_file:
                    content = run_command(f'cat "{cron_file}" 2>/dev/null')
                    for line in content.split('\n'):
                        if line and not line.startswith('#'):
                            # Extract script paths
                            import re
                            script_paths = re.findall(r'/[^\s]+\.(?:sh|py|pl|rb)', line)
                            for script_path in script_paths:
                                if os.path.exists(script_path):
                                    perms = run_command(f'ls -la "{script_path}"')
                                    if perms and 'rw-' in perms[7:10]:  # Others writable
                                        findings.append({
                                            'type': 'cron',
                                            'description': f'Writable cron script: {script_path}',
                                            'details': {
                                                'script': script_path,
                                                'cron_file': cron_file,
                                                'cron_line': line.strip(),
                                                'permissions': perms
                                            },
                                            'mitigation': f'Fix script permissions: chmod o-w {script_path}'
                                        })
    
    # Check user crontabs
    users = run_command('cut -d: -f1 /etc/passwd')
    for user in users.split('\n'):
        if user:
            user_cron = run_command(f'crontab -u {user} -l 2>/dev/null')
            if user_cron and 'no crontab' not in user_cron:
                for line in user_cron.split('\n'):
                    if line and not line.startswith('#'):
                        # Check for PATH manipulation
                        if line.startswith('PATH=') and '/tmp' in line:
                            findings.append({
                                'type': 'cron',
                                'description': f'Dangerous PATH in {user} crontab',
                                'details': {'user': user, 'path_line': line},
                                'mitigation': f'Remove writable directories from PATH in {user} crontab'
                            })
    
    # Check systemd timers
    timers = run_command('systemctl list-timers --all --no-pager 2>/dev/null')
    if timers:
        for line in timers.split('\n')[1:]:  # Skip header
            if '.timer' in line:
                timer_name = line.split()[0] if line.split() else ''
                if timer_name:
                    # Get timer unit file
                    timer_file = run_command(f'systemctl show -p FragmentPath {timer_name} 2>/dev/null')
                    if timer_file and 'FragmentPath=' in timer_file:
                        timer_path = timer_file.split('=')[1]
                        if os.path.exists(timer_path):
                            perms = run_command(f'ls -la "{timer_path}"')
                            if perms and 'rw-' in perms[7:10]:  # Others writable
                                findings.append({
                                    'type': 'cron',
                                    'description': f'Writable systemd timer: {timer_name}',
                                    'details': {'timer': timer_name, 'file': timer_path, 'permissions': perms},
                                    'mitigation': f'Fix permissions: chmod 644 {timer_path}'
                                })
    
    # Check systemd service files for timers
    service_dirs = ['/etc/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system']
    for service_dir in service_dirs:
        if os.path.exists(service_dir):
            timer_files = run_command(f'find {service_dir} -name "*.timer" 2>/dev/null')
            for timer_file in timer_files.split('\n'):
                if timer_file:
                    # Check if timer file is writable
                    perms = run_command(f'ls -la "{timer_file}"')
                    if perms and 'rw-' in perms[7:10]:  # Others writable
                        findings.append({
                            'type': 'cron',
                            'description': f'Writable systemd timer file: {timer_file}',
                            'details': {'file': timer_file, 'permissions': perms},
                            'mitigation': f'Fix permissions: chmod 644 {timer_file}'
                        })
                    
                    # Check associated service file
                    service_name = os.path.basename(timer_file).replace('.timer', '.service')
                    service_file = os.path.join(os.path.dirname(timer_file), service_name)
                    if os.path.exists(service_file):
                        service_content = run_command(f'cat "{service_file}" 2>/dev/null')
                        if 'ExecStart=' in service_content:
                            for line in service_content.split('\n'):
                                if line.startswith('ExecStart='):
                                    exec_path = line.split('=', 1)[1].split()[0]
                                    if os.path.exists(exec_path):
                                        exec_perms = run_command(f'ls -la "{exec_path}"')
                                        if exec_perms and 'rw-' in exec_perms[7:10]:
                                            findings.append({
                                                'type': 'cron',
                                                'description': f'Writable systemd timer executable: {exec_path}',
                                                'details': {
                                                    'executable': exec_path,
                                                    'service': service_file,
                                                    'timer': timer_file,
                                                    'permissions': exec_perms
                                                },
                                                'mitigation': f'Fix executable permissions: chmod o-w {exec_path}'
                                            })
    
    return findings