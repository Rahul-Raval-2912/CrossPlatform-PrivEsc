"""
False Positive Filter Module
Final validation layer to prevent false positives across all modules
"""

import os
import re

class FalsePositiveFilter:
    def __init__(self):
        # Known false positive patterns
        self.windows_false_positives = {
            'system_services': [
                'svchost.exe', 'services.exe', 'lsass.exe', 'winlogon.exe',
                'csrss.exe', 'wininit.exe', 'smss.exe'
            ],
            'system_paths': [
                'c:\\windows\\system32\\',
                'c:\\windows\\syswow64\\',
                'c:\\program files\\windows defender\\',
                'c:\\program files (x86)\\windows defender\\',
                'c:\\windows\\winsxs\\'
            ],
            'normal_registry_keys': [
                'hklm\\software\\microsoft\\windows\\currentversion\\run',
                'hkcu\\software\\microsoft\\windows\\currentversion\\run'
            ]
        }
        
        self.linux_false_positives = {
            'system_binaries': [
                '/bin/su', '/bin/sudo', '/usr/bin/sudo', '/bin/mount',
                '/bin/umount', '/usr/bin/passwd', '/bin/ping'
            ],
            'system_paths': [
                '/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/',
                '/lib/', '/usr/lib/', '/lib64/', '/usr/lib64/'
            ]
        }
    
    def is_windows_false_positive(self, finding):
        """Check if Windows finding is a false positive"""
        description = finding.get('description', '').lower()
        details = str(finding.get('details', {})).lower()
        
        # Check for system service false positives
        if finding.get('type') == 'service':
            for sys_service in self.windows_false_positives['system_services']:
                if sys_service in description or sys_service in details:
                    return True
            
            # Check for system path false positives
            for sys_path in self.windows_false_positives['system_paths']:
                if sys_path in details:
                    return True
        
        # Check for normal registry entries
        if finding.get('type') == 'registry':
            for normal_key in self.windows_false_positives['normal_registry_keys']:
                if normal_key in details and 'suspicious' not in description:
                    return True
        
        return False
    
    def is_linux_false_positive(self, finding):
        """Check if Linux finding is a false positive"""
        description = finding.get('description', '').lower()
        details = str(finding.get('details', {})).lower()
        
        # Check for normal system SUID binaries
        if finding.get('type') == 'suid':
            path = finding.get('details', {}).get('path', '')
            if path in self.linux_false_positives['system_binaries']:
                return True
            
            # Check if it's in system directories and not actually dangerous
            for sys_path in self.linux_false_positives['system_paths']:
                if path.startswith(sys_path) and 'gtfobins' not in description:
                    return True
        
        return False
    
    def filter_findings(self, findings, platform):
        """Filter out false positives from findings"""
        filtered_findings = []
        
        for finding in findings:
            is_false_positive = False
            
            if platform.lower() == 'windows':
                is_false_positive = self.is_windows_false_positive(finding)
            elif platform.lower() == 'linux':
                is_false_positive = self.is_linux_false_positive(finding)
            
            if not is_false_positive:
                filtered_findings.append(finding)
        
        return filtered_findings
    
    def validate_finding_quality(self, finding):
        """Validate finding quality and completeness"""
        required_fields = ['type', 'description']
        
        # Check required fields
        for field in required_fields:
            if field not in finding or not finding[field]:
                return False
        
        # Check for meaningful description
        description = finding['description']
        if len(description) < 10 or description.lower() in ['unknown', 'error', 'none']:
            return False
        
        return True