#!/usr/bin/env python3
"""
PrivEsc-Framework v2.0: Advanced Cross-Platform Privilege Escalation Enumeration
Enhanced with container detection, network analysis, AD checks, and exploit suggestions
Final version with false positive filtering
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
    from core.exploit_engine import ExploitSuggestionEngine
    from core.false_positive_filter import FalsePositiveFilter
except ImportError as e:
    print(f"[!] Import error: {e}")
    print("[!] Make sure all required files are present")
    sys.exit(1)

class PrivEscFramework:
    def __init__(self):
        self.os_detector = OSDetector()
        self.privilege_checker = PrivilegeChecker()
        self.report_engine = ReportEngine()
        self.exploit_engine = ExploitSuggestionEngine()
        self.fp_filter = FalsePositiveFilter()
        self.findings = []
    
    def run_enumeration(self, output_format='json', output_file=None, include_exploits=False):
        """Execute advanced privilege escalation enumeration"""
        print("[+] PrivEsc-Framework v2.0 - Advanced Privilege Escalation Enumeration")
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
                from linux import enum_users, enum_sudo, enum_suid, enum_cron, enum_kernel, enum_containers, enum_network
                modules = [
                    ('linux.enum_users', enum_users),
                    ('linux.enum_sudo', enum_sudo),
                    ('linux.enum_suid', enum_suid),
                    ('linux.enum_cron', enum_cron),
                    ('linux.enum_kernel', enum_kernel),
                    ('linux.enum_containers', enum_containers),
                    ('linux.enum_network', enum_network)
                ]
            except ImportError as e:
                print(f"[!] Failed to import Linux modules: {e}")
                return
                
        elif os_info['platform'] == 'Windows':
            try:
                from windows import enum_services, enum_registry, enum_tokens, enum_scheduled_tasks, enum_active_directory
                modules = [
                    ('windows.enum_services', enum_services),
                    ('windows.enum_registry', enum_registry),
                    ('windows.enum_tokens', enum_tokens),
                    ('windows.enum_scheduled_tasks', enum_scheduled_tasks),
                    ('windows.enum_active_directory', enum_active_directory)
                ]
            except ImportError as e:
                print(f"[!] Failed to import Windows modules: {e}")
                return
        else:
            print(f"[-] Unsupported platform: {os_info['platform']}")
            return
        
        # Execute enumeration modules
        print("\n[+] Starting advanced enumeration modules...")
        raw_findings = []
        
        for module_name, module in modules:
            try:
                print(f"[*] Running {module_name}...")
                module_findings = module.enumerate()
                
                # Basic validation
                valid_findings = []
                for finding in module_findings:
                    if (isinstance(finding, dict) and 
                        'type' in finding and 
                        'description' in finding and
                        self.fp_filter.validate_finding_quality(finding)):
                        valid_findings.append(finding)
                
                raw_findings.extend(valid_findings)
                print(f"[✓] {module_name} completed - {len(valid_findings)} findings")
                
            except Exception as e:
                print(f"[!] {module_name} failed: {e}")
                continue
        
        # Apply false positive filtering
        print(f"[+] Applying false positive filtering...")
        self.findings = self.fp_filter.filter_findings(raw_findings, os_info['platform'])
        
        filtered_count = len(raw_findings) - len(self.findings)
        if filtered_count > 0:
            print(f"[+] Filtered out {filtered_count} false positives")
        
        print(f"[+] Final findings: {len(self.findings)}")
        
        # Generate exploit suggestions if requested
        exploit_suggestions = []
        if include_exploits and self.findings:
            print("[+] Generating exploit suggestions...")
            exploit_suggestions = self.exploit_engine.generate_exploit_report(self.findings, os_info)
            print(f"[+] Generated {len(exploit_suggestions)} exploit suggestions")
        
        # Generate report
        if self.findings or exploit_suggestions:
            self.report_engine.generate_report(
                self.findings, 
                os_info, 
                priv_info, 
                output_format, 
                output_file,
                exploit_suggestions
            )
        else:
            print("[+] No privilege escalation vulnerabilities found.")
            print("[+] System appears to be properly configured.")

def main():
    try:
        parser = argparse.ArgumentParser(description='PrivEsc-Framework v2.0 - Advanced Cross-Platform Privilege Escalation Enumeration')
        parser.add_argument('-f', '--format', choices=['json', 'txt'], default='json', help='Output format')
        parser.add_argument('-o', '--output', help='Output file path')
        parser.add_argument('-e', '--exploits', action='store_true', help='Include exploit suggestions (use responsibly)')
        parser.add_argument('--verbose', action='store_true', help='Verbose output')
        
        args = parser.parse_args()
        
        if args.exploits:
            print("[!] WARNING: Exploit suggestions enabled - use only for authorized testing!")
            print("[!] The authors are not responsible for misuse of this feature.")
        
        framework = PrivEscFramework()
        framework.run_enumeration(args.format, args.output, args.exploits)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()