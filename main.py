#!/usr/bin/env python3
"""
PrivEsc-Framework: Professional Cross-Platform Privilege Escalation Enumeration
Fixed Windows compatibility and scoring issues
"""

import sys
import argparse
import platform
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

try:
    from core.os_detector import OSDetector
    from core.privilege_checker import PrivilegeChecker
    from core.report_engine import ReportEngine
except ImportError as e:
    print(f"[!] Import error: {e}")
    print("[!] Make sure all required files are present")
    sys.exit(1)

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
        print(f"[+] Target OS: {os_info.get('platform', 'Unknown')} {os_info.get('version', '')}")
        
        # Check current privileges
        priv_info = self.privilege_checker.check_privileges()
        print(f"[+] Current User: {priv_info.get('user', 'Unknown')} (Privileges: {priv_info.get('level', 'Unknown')})")
        
        # Load platform-specific modules
        if os_info['platform'] == 'Linux':
            try:
                from linux import enum_users, enum_sudo, enum_suid, enum_cron, enum_kernel
                modules = [
                    ('linux.enum_users', enum_users),
                    ('linux.enum_sudo', enum_sudo),
                    ('linux.enum_suid', enum_suid),
                    ('linux.enum_cron', enum_cron),
                    ('linux.enum_kernel', enum_kernel)
                ]
            except ImportError as e:
                print(f"[!] Failed to import Linux modules: {e}")
                return
                
        elif os_info['platform'] == 'Windows':
            try:
                from windows import enum_services, enum_registry, enum_tokens, enum_scheduled_tasks
                modules = [
                    ('windows.enum_services', enum_services),
                    ('windows.enum_registry', enum_registry),
                    ('windows.enum_tokens', enum_tokens),
                    ('windows.enum_scheduled_tasks', enum_scheduled_tasks)
                ]
            except ImportError as e:
                print(f"[!] Failed to import Windows modules: {e}")
                return
        else:
            print(f"[-] Unsupported platform: {os_info['platform']}")
            return
        
        # Execute enumeration modules
        print("\n[+] Starting enumeration modules...")
        total_findings = 0
        
        for module_name, module in modules:
            try:
                print(f"[*] Running {module_name}...")
                module_findings = module.enumerate()
                
                # Filter out duplicate or invalid findings
                valid_findings = []
                for finding in module_findings:
                    if isinstance(finding, dict) and 'type' in finding and 'description' in finding:
                        valid_findings.append(finding)
                
                self.findings.extend(valid_findings)
                total_findings += len(valid_findings)
                print(f"[✓] {module_name} completed - {len(valid_findings)} findings")
                
            except Exception as e:
                print(f"[!] {module_name} failed: {e}")
                continue
        
        print(f"\n[+] Total findings collected: {total_findings}")
        
        # Generate report
        if self.findings:
            self.report_engine.generate_report(
                self.findings, 
                os_info, 
                priv_info, 
                output_format, 
                output_file
            )
        else:
            print("[+] No privilege escalation vulnerabilities found.")
            print("[+] System appears to be properly configured.")

def main():
    try:
        parser = argparse.ArgumentParser(description='PrivEsc-Framework - Cross-Platform Privilege Escalation Enumeration')
        parser.add_argument('-f', '--format', choices=['json', 'txt'], default='json', help='Output format')
        parser.add_argument('-o', '--output', help='Output file path')
        parser.add_argument('--verbose', action='store_true', help='Verbose output')
        
        args = parser.parse_args()
        
        framework = PrivEscFramework()
        framework.run_enumeration(args.format, args.output)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()