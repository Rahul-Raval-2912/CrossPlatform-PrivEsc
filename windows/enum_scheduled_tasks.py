"""
Windows Scheduled Tasks Enumeration Module - Reduced False Positives
Identifies genuine scheduled task-based privilege escalation opportunities
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

def is_system_protected_path(path):
    """Check if path is system-protected"""
    protected_paths = [
        'c:\\windows\\system32\\',
        'c:\\windows\\syswow64\\',
        'c:\\program files\\windows defender\\',
        'c:\\program files (x86)\\windows defender\\'
    ]
    
    path_lower = path.lower()
    return any(path_lower.startswith(protected) for protected in protected_paths)

def enumerate():
    """Enumerate Windows scheduled task vulnerabilities - Fixed"""
    findings = []
    
    # Get scheduled tasks with custom executables only
    schtasks_output = run_command('schtasks /query /fo CSV /v')
    
    if schtasks_output:
        lines = schtasks_output.split('\n')[1:]  # Skip header
        processed_tasks = set()
        
        for line in lines:
            if line and ',' in line:
                # Parse CSV line
                parts = [part.strip('"') for part in line.split('","')]
                if len(parts) > 10:
                    task_name = parts[0]
                    run_as_user = parts[9] if len(parts) > 9 else ''
                    task_to_run = parts[10] if len(parts) > 10 else ''
                    
                    # Skip duplicates and empty tasks
                    if not task_name or not task_to_run or task_name in processed_tasks:
                        continue
                    
                    processed_tasks.add(task_name)
                    
                    # Only check tasks running as SYSTEM/Administrator with custom executables
                    if any(user in run_as_user.upper() for user in ['SYSTEM', 'ADMINISTRATOR']):
                        
                        # Extract executable path
                        exe_path = task_to_run.split()[0].strip('"') if task_to_run.split() else ''
                        
                        # Skip system-protected paths
                        if is_system_protected_path(exe_path):
                            continue
                        
                        # Check for writable task executables (non-system only)
                        if exe_path and os.path.exists(exe_path):
                            try:
                                # Try to open file for writing
                                with open(exe_path, 'r+b'):
                                    pass
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
                            except (PermissionError, OSError):
                                # File is not writable - this is normal
                                pass
                        
                        # Check for unquoted paths with spaces (non-system paths only)
                        if (' ' in task_to_run and 
                            not (task_to_run.startswith('"') and '"' in task_to_run[1:]) and
                            not is_system_protected_path(exe_path)):
                            
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
                                break
    
    # Check for tasks with missing executables (potential DLL hijacking)
    missing_exe_output = run_command('schtasks /query /fo LIST | findstr /C:"Task To Run"')
    if missing_exe_output:
        for line in missing_exe_output.split('\n'):
            if 'Task To Run:' in line:
                exe_path = line.split(':', 1)[1].strip().split()[0].strip('"')
                if exe_path and not os.path.exists(exe_path) and not is_system_protected_path(exe_path):
                    findings.append({
                        'type': 'scheduled_task',
                        'description': f'Scheduled task with missing executable: {exe_path}',
                        'details': {
                            'missing_executable': exe_path,
                            'opportunity': 'DLL hijacking or executable replacement'
                        },
                        'mitigation': f'Fix or remove task with missing executable: {exe_path}'
                    })
    
    return findings