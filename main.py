#!/usr/bin/env python3
"""
PrivEsc-Framework: Professional Cross-Platform Privilege Escalation Enumeration
Main entry point for the framework
"""

import sys
import argparse
from pathlib import Path
from core.os_detector import OSDetector
from core.privilege_checker import PrivilegeChecker
from core.report_engine import ReportEngine

class PrivEscFramework:
    def __init__(self):
        self.os_detector = OSDetector()
        self.privilege_checker = PrivilegeChecker()
        self.report_engine = ReportEngine()
        self.findings = []
    
    def run_enumeration(self, output_format='json', output_file=None):
        """Execute privilege escalation enumeration"""
        print("[+] PrivEsc-Framework v1.0 - Professional Privilege Escalation Enumeration")
        print("=" * 70)
        
        # Detect OS and load appropriate modules
        os_info = self.os_detector.detect()
        print(f"[+] Target OS: {os_info['platform']} {os_info['version']}")
        
        # Check current privileges
        priv_info = self.privilege_checker.check_privileges()
        print(f"[+] Current User: {priv_info['user']} (Privileges: {priv_info['level']})")
        
        # Load platform-specific modules
        if os_info['platform'] == 'Linux':
            from linux import enum_users, enum_sudo, enum_suid, enum_cron, enum_kernel
            modules = [enum_users, enum_sudo, enum_suid, enum_cron, enum_kernel]
        elif os_info['platform'] == 'Windows':
            from windows import enum_services, enum_registry, enum_tokens, enum_scheduled_tasks
            modules = [enum_services, enum_registry, enum_tokens, enum_scheduled_tasks]
        else:
            print(f"[-] Unsupported platform: {os_info['platform']}")
            return
        
        # Execute enumeration modules
        print("\n[+] Starting enumeration modules...")
        for module in modules:
            try:
                module_findings = module.enumerate()
                self.findings.extend(module_findings)
                print(f"[✓] {module.__name__} completed")
            except Exception as e:
                print(f"[!] {module.__name__} failed: {e}")
        
        # Generate report
        self.report_engine.generate_report(
            self.findings, 
            os_info, 
            priv_info, 
            output_format, 
            output_file
        )

def main():
    parser = argparse.ArgumentParser(description='PrivEsc-Framework - Cross-Platform Privilege Escalation Enumeration')
    parser.add_argument('-f', '--format', choices=['json', 'txt'], default='json', help='Output format')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    framework = PrivEscFramework()
    framework.run_enumeration(args.format, args.output)

if __name__ == "__main__":
    main()