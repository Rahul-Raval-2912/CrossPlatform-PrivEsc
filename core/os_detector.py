"""
OS Detection Module
Identifies target operating system and version
"""

import platform
import subprocess
import os

class OSDetector:
    def __init__(self):
        self.os_info = {}
    
    def detect(self):
        """Detect operating system and gather basic info"""
        system = platform.system()
        
        if system == "Linux":
            return self._detect_linux()
        elif system == "Windows":
            return self._detect_windows()
        else:
            return {
                'platform': system,
                'version': platform.release(),
                'architecture': platform.machine(),
                'supported': False
            }
    
    def _detect_linux(self):
        """Linux-specific detection"""
        try:
            # Get distribution info
            with open('/etc/os-release', 'r') as f:
                os_release = f.read()
            
            distro = "Unknown"
            version = "Unknown"
            
            for line in os_release.split('\n'):
                if line.startswith('NAME='):
                    distro = line.split('=')[1].strip('"')
                elif line.startswith('VERSION='):
                    version = line.split('=')[1].strip('"')
            
            return {
                'platform': 'Linux',
                'distribution': distro,
                'version': version,
                'kernel': platform.release(),
                'architecture': platform.machine(),
                'supported': True
            }
        except:
            return {
                'platform': 'Linux',
                'distribution': 'Unknown',
                'version': platform.release(),
                'kernel': platform.release(),
                'architecture': platform.machine(),
                'supported': True
            }
    
    def _detect_windows(self):
        """Windows-specific detection"""
        try:
            version = platform.version()
            release = platform.release()
            
            return {
                'platform': 'Windows',
                'version': f"{release} {version}",
                'architecture': platform.machine(),
                'supported': True
            }
        except:
            return {
                'platform': 'Windows',
                'version': 'Unknown',
                'architecture': platform.machine(),
                'supported': True
            }