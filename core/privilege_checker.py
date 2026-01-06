"""
Privilege Checker Module
Assesses current user privileges and context
"""

import os
import subprocess
import platform

class PrivilegeChecker:
    def __init__(self):
        self.system = platform.system()
    
    def check_privileges(self):
        """Check current user privileges"""
        if self.system == "Linux":
            return self._check_linux_privileges()
        elif self.system == "Windows":
            return self._check_windows_privileges()
        else:
            return {'user': 'unknown', 'level': 'unknown'}
    
    def _check_linux_privileges(self):
        """Check Linux user privileges"""
        try:
            user = os.getenv('USER', 'unknown')
            uid = os.getuid()
            gid = os.getgid()
            
            # Check if root
            if uid == 0:
                level = 'root'
            else:
                # Check sudo access
                try:
                    result = subprocess.run(['sudo', '-n', 'true'], 
                                          capture_output=True, timeout=5)
                    if result.returncode == 0:
                        level = 'sudo'
                    else:
                        level = 'user'
                except:
                    level = 'user'
            
            # Get groups
            try:
                groups = subprocess.run(['groups'], capture_output=True, text=True)
                group_list = groups.stdout.strip().split()
            except:
                group_list = []
            
            return {
                'user': user,
                'uid': uid,
                'gid': gid,
                'level': level,
                'groups': group_list
            }
        except:
            return {'user': 'unknown', 'level': 'unknown'}
    
    def _check_windows_privileges(self):
        """Check Windows user privileges"""
        try:
            user = os.getenv('USERNAME', 'unknown')
            
            # Check if admin
            try:
                result = subprocess.run(['net', 'session'], 
                                      capture_output=True, timeout=5)
                if result.returncode == 0:
                    level = 'admin'
                else:
                    level = 'user'
            except:
                level = 'user'
            
            return {
                'user': user,
                'level': level,
                'domain': os.getenv('USERDOMAIN', 'unknown')
            }
        except:
            return {'user': 'unknown', 'level': 'unknown'}