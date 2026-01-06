"""
Windows Scheduled Tasks Enumeration Module
Identifies scheduled task-based privilege escalation opportunities
"""

import subprocess
import re
import os

def run_command(cmd):
    """Execute command and return output"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.stdout.strip()
    except:
        return ""

def enumerate():
    """Enumerate Windows scheduled task vulnerabilities"""
    findings = []
    
    # Get all scheduled tasks
    schtasks_output = run_command('schtasks /query /fo LIST /v')
    
    if schtasks_output:
        # Parse tasks
        tasks = schtasks_output.split('\n\n')
        
        for task_block in tasks:
            if 'TaskName:' in task_block:
                task_info = {}
                
                # Extract task information
                for line in task_block.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        task_info[key.strip()] = value.strip()
                
                task_name = task_info.get('TaskName', 'Unknown')
                run_as_user = task_info.get('Run As User', 'Unknown')
                task_to_run = task_info.get('Task To Run', '')
                
                # Check for tasks running as SYSTEM or Administrator
                if any(user in run_as_user.upper() for user in ['SYSTEM', 'ADMINISTRATOR', 'NT AUTHORITY']):
                    
                    # Check for writable task executables
                    if task_to_run:
                        # Extract executable path
                        exe_path = task_to_run.split()[0].strip('"') if task_to_run.split() else ''
                        
                        if exe_path and os.path.exists(exe_path):
                            try:
                                if os.access(exe_path, os.W_OK):
                                    findings.append({
                                        'type': 'scheduled_task',
                                        'description': f'Writable high-privilege scheduled task: {task_name}',
                                        'details': {
                                            'task_name': task_name,
                                            'executable': exe_path,
                                            'run_as': run_as_user,
                                            'command': task_to_run
                                        },
                                        'mitigation': f'Secure permissions on {exe_path}'
                                    })
                            except:
                                pass
                        
                        # Check for unquoted paths with spaces
                        if ' ' in task_to_run and not (task_to_run.startswith('"') and '"' in task_to_run[1:]):
                            findings.append({
                                'type': 'scheduled_task',
                                'description': f'Unquoted path in scheduled task: {task_name}',
                                'details': {
                                    'task_name': task_name,
                                    'command': task_to_run,
                                    'run_as': run_as_user
                                },
                                'mitigation': f'Quote the path in scheduled task: {task_name}'
                            })
                        
                        # Check for tasks in writable directories
                        writable_dirs = ['C:\\temp', 'C:\\tmp', 'C:\\Users\\Public']
                        for writable_dir in writable_dirs:
                            if task_to_run.lower().startswith(writable_dir.lower()):
                                findings.append({
                                    'type': 'scheduled_task',
                                    'description': f'High-privilege task in writable directory: {task_name}',
                                    'details': {
                                        'task_name': task_name,
                                        'directory': writable_dir,
                                        'command': task_to_run,
                                        'run_as': run_as_user
                                    },
                                    'mitigation': f'Move task executable to secure location'
                                })
    
    # Check task scheduler permissions
    task_scheduler_perms = run_command('icacls C:\\Windows\\System32\\Tasks')
    if task_scheduler_perms:
        # Look for write permissions for non-admin users
        if 'Everyone:(W)' in task_scheduler_perms or 'Users:(W)' in task_scheduler_perms:
            findings.append({
                'type': 'scheduled_task',
                'description': 'Weak permissions on Tasks directory',
                'details': {
                    'directory': 'C:\\Windows\\System32\\Tasks',
                    'permissions': task_scheduler_perms
                },
                'mitigation': 'Restrict write permissions on Tasks directory'
            })
    
    # Check for tasks with missing executables (DLL hijacking opportunity)
    missing_exe_tasks = run_command('schtasks /query /fo LIST | findstr /C:"Task To Run"')
    if missing_exe_tasks:
        for line in missing_exe_tasks.split('\n'):
            if 'Task To Run:' in line:
                exe_path = line.split(':', 1)[1].strip().split()[0].strip('"')
                if exe_path and not os.path.exists(exe_path):
                    findings.append({
                        'type': 'scheduled_task',
                        'description': f'Scheduled task with missing executable: {exe_path}',
                        'details': {
                            'missing_executable': exe_path,
                            'opportunity': 'DLL hijacking or executable replacement'
                        },
                        'mitigation': f'Fix or remove task with missing executable: {exe_path}'
                    })
    
    # Check for tasks running scripts in writable locations
    script_extensions = ['.bat', '.cmd', '.ps1', '.vbs', '.js']
    script_tasks = run_command('schtasks /query /fo LIST | findstr /C:"Task To Run"')
    
    if script_tasks:
        for line in script_tasks.split('\n'):
            if 'Task To Run:' in line:
                command = line.split(':', 1)[1].strip()
                
                for ext in script_extensions:
                    if ext.lower() in command.lower():
                        # Extract script path
                        script_match = re.search(rf'([C-Z]:[^"]*{re.escape(ext)})', command, re.IGNORECASE)
                        if script_match:
                            script_path = script_match.group(1)
                            
                            if os.path.exists(script_path):
                                try:
                                    if os.access(script_path, os.W_OK):
                                        findings.append({
                                            'type': 'scheduled_task',
                                            'description': f'Writable script in scheduled task: {script_path}',
                                            'details': {
                                                'script_path': script_path,
                                                'command': command,
                                                'extension': ext
                                            },
                                            'mitigation': f'Secure permissions on script: {script_path}'
                                        })
                                except:
                                    pass
    
    # Check for tasks with weak authentication (no password required)
    no_password_tasks = run_command('schtasks /query /fo LIST /v | findstr /C:"Logon Mode"')
    if no_password_tasks:
        for line in no_password_tasks.split('\n'):
            if 'Interactive/Background' in line or 'Interactive only' in line:
                findings.append({
                    'type': 'scheduled_task',
                    'description': 'Scheduled task with interactive logon mode',
                    'details': {
                        'logon_mode': line.strip(),
                        'risk': 'May not require password for execution'
                    },
                    'mitigation': 'Review task authentication requirements'
                })
    
    return findings