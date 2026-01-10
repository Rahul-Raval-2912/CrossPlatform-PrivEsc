"""
Report Engine Module v2.0 - Enhanced with Exploit Suggestions
Professional reporting with improved formatting and exploit recommendations
"""

import json
from datetime import datetime

class ReportEngine:
    def __init__(self):
        self.mitre_mapping = {
            'T1068': 'Exploitation for Privilege Escalation',
            'T1548': 'Abuse Elevation Control Mechanism',
            'T1053': 'Scheduled Task/Job',
            'T1574': 'Hijack Execution Flow',
            'T1055': 'Process Injection',
            'T1134': 'Access Token Manipulation',
            'T1087': 'Account Discovery',
            'T1610': 'Deploy Container'
        }
        
        self.risk_scores = {
            'Critical': 9.0,
            'High': 7.0,
            'Medium': 5.0,
            'Low': 3.0
        }
        
        # Color codes for better visual output
        self.colors = {
            'Critical': '\033[91m',  # Red
            'High': '\033[93m',      # Yellow
            'Medium': '\033[94m',    # Blue
            'Low': '\033[92m',       # Green
            'reset': '\033[0m',      # Reset
            'bold': '\033[1m',       # Bold
            'header': '\033[95m'     # Magenta
        }
    
    def calculate_risk_score(self, findings):
        """Calculate overall risk score"""
        if not findings:
            return 0.0
        
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for finding in findings:
            severity = finding.get('severity', 'Low')
            severity_counts[severity] += 1
        
        total_weight = 0
        weighted_score = 0
        
        for severity, count in severity_counts.items():
            if count > 0:
                weight = self.risk_scores[severity]
                weighted_score += weight * count
                total_weight += count
        
        if total_weight == 0:
            return 0.0
            
        average_score = weighted_score / total_weight
        return min(average_score, 10.0)
    
    def classify_severity(self, finding_type, details):
        """Enhanced severity classification"""
        description = details.get('description', '').lower()
        finding_details = str(details.get('details', {})).lower()
        
        # Critical patterns
        critical_patterns = [
            'system service', 'administrator', 'root', 'suid', 'setuid',
            'alwaysinstallelevated', 'sedebugprivilege', 'setakeownershipprivilege',
            'sebackupprivilege', 'serestoreprivilege', 'writable system binary',
            'container escape', 'docker socket', 'privileged container'
        ]
        
        # High patterns
        high_patterns = [
            'sudo', 'nopasswd', 'service', 'cron', 'scheduled', 'admin',
            'writable binary', 'unquoted path', 'dangerous privilege',
            'seimpersonateprivilege', 'token manipulation', 'gtfobins',
            'docker group', 'lxd group', 'active directory'
        ]
        
        # Medium patterns
        medium_patterns = [
            'writable', 'permission', 'weak acl', 'misconfigured',
            'registry', 'autorun', 'credential', 'outdated kernel',
            'network service', 'ssh', 'nfs'
        ]
        
        text_to_check = f"{description} {finding_details}"
        
        if any(pattern in text_to_check for pattern in critical_patterns):
            return 'Critical'
        elif any(pattern in text_to_check for pattern in high_patterns):
            return 'High'
        elif any(pattern in text_to_check for pattern in medium_patterns):
            return 'Medium'
        else:
            return 'Low'
    
    def map_to_mitre(self, finding_type):
        """Map finding to MITRE ATT&CK technique"""
        mapping = {
            'suid': 'T1548.001',
            'sudo': 'T1548.003',
            'cron': 'T1053.003',
            'service': 'T1543.002',
            'token': 'T1134',
            'registry': 'T1574.011',
            'scheduled_task': 'T1053.005',
            'user_enum': 'T1087',
            'kernel': 'T1068',
            'container': 'T1610',
            'network': 'T1046',
            'active_directory': 'T1087.002'
        }
        return mapping.get(finding_type.lower(), 'T1068')
    
    def get_risk_level_description(self, score):
        """Get risk level description"""
        if score >= 8.0:
            return "CRITICAL RISK - Immediate attention required"
        elif score >= 6.0:
            return "HIGH RISK - Significant security concerns"
        elif score >= 4.0:
            return "MEDIUM RISK - Security improvements needed"
        elif score >= 2.0:
            return "LOW RISK - Minor security issues"
        else:
            return "MINIMAL RISK - Good security posture"
    
    def generate_report(self, findings, os_info, priv_info, output_format='json', output_file=None, exploit_suggestions=None):
        """Generate enhanced professional report with exploit suggestions"""
        
        # Process and deduplicate findings
        processed_findings = []
        seen_findings = set()
        
        for finding in findings:
            finding_id = f"{finding['type']}_{finding['description']}"
            if finding_id in seen_findings:
                continue
            seen_findings.add(finding_id)
            
            severity = self.classify_severity(finding['type'], finding)
            mitre_id = self.map_to_mitre(finding['type'])
            
            processed_finding = {
                'id': len(processed_findings) + 1,
                'type': finding['type'],
                'severity': severity,
                'description': finding['description'],
                'details': finding.get('details', {}),
                'mitigation': finding.get('mitigation', ''),
                'mitre_attack': {
                    'technique_id': mitre_id,
                    'technique_name': self.mitre_mapping.get(mitre_id.split('.')[0], 'Unknown')
                },
                'risk_score': self.risk_scores[severity]
            }
            processed_findings.append(processed_finding)
        
        # Calculate overall risk
        overall_risk = self.calculate_risk_score(processed_findings)
        risk_description = self.get_risk_level_description(overall_risk)
        
        # Generate report data
        report_data = {
            'metadata': {
                'framework': 'PrivEsc-Framework v2.0',
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'target_os': os_info,
                'current_user': priv_info,
                'total_findings': len(processed_findings),
                'overall_risk_score': round(overall_risk, 1),
                'risk_level': risk_description,
                'exploit_suggestions_count': len(exploit_suggestions) if exploit_suggestions else 0
            },
            'summary': {
                'critical': len([f for f in processed_findings if f['severity'] == 'Critical']),
                'high': len([f for f in processed_findings if f['severity'] == 'High']),
                'medium': len([f for f in processed_findings if f['severity'] == 'Medium']),
                'low': len([f for f in processed_findings if f['severity'] == 'Low'])
            },
            'findings': processed_findings,
            'exploit_suggestions': exploit_suggestions or []
        }
        
        # Output report
        if output_format == 'json':
            self._output_json(report_data, output_file)
        elif output_format == 'txt':
            self._output_txt(report_data, output_file)
        
        # Console summary
        self._print_summary(report_data)
    
    def _print_summary(self, data):
        """Print enhanced console summary"""
        print(f"\n{self.colors['header']}{'='*70}{self.colors['reset']}")
        print(f"{self.colors['bold']}SCAN COMPLETED - ADVANCED SECURITY REPORT{self.colors['reset']}")
        print(f"{self.colors['header']}{'='*70}{self.colors['reset']}")
        
        print(f"{self.colors['bold']}Total Findings:{self.colors['reset']} {data['metadata']['total_findings']}")
        print(f"{self.colors['bold']}Risk Assessment:{self.colors['reset']} {data['metadata']['risk_level']}")
        print(f"{self.colors['bold']}Overall Score:{self.colors['reset']} {data['metadata']['overall_risk_score']}/10.0")
        
        if data['metadata']['exploit_suggestions_count'] > 0:
            print(f"{self.colors['bold']}Exploit Suggestions:{self.colors['reset']} {data['metadata']['exploit_suggestions_count']}")
        
        print(f"\n{self.colors['bold']}Findings Breakdown:{self.colors['reset']}")
        if data['summary']['critical'] > 0:
            print(f"  {self.colors['Critical']}🔴 Critical: {data['summary']['critical']}{self.colors['reset']}")
        if data['summary']['high'] > 0:
            print(f"  {self.colors['High']}🟡 High: {data['summary']['high']}{self.colors['reset']}")
        if data['summary']['medium'] > 0:
            print(f"  {self.colors['Medium']}🔵 Medium: {data['summary']['medium']}{self.colors['reset']}")
        if data['summary']['low'] > 0:
            print(f"  {self.colors['Low']}🟢 Low: {data['summary']['low']}{self.colors['reset']}")
        
        if data['metadata']['total_findings'] == 0:
            print(f"  {self.colors['Low']}✅ No vulnerabilities found - System appears secure{self.colors['reset']}")
    
    def _output_json(self, data, output_file):
        """Output JSON format"""
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"\n{self.colors['bold']}JSON report saved:{self.colors['reset']} {output_file}")
        else:
            print(json.dumps(data, indent=2))
    
    def _output_txt(self, data, output_file):
        """Output enhanced text format with exploit suggestions"""
        output = []
        
        # Header
        output.append("╔" + "═" * 68 + "╗")
        output.append("║" + " PRIVESC-FRAMEWORK v2.0 SECURITY ASSESSMENT ".center(68) + "║")
        output.append("╚" + "═" * 68 + "╝")
        output.append("")
        
        # Metadata
        output.append("📊 SCAN INFORMATION")
        output.append("─" * 50)
        output.append(f"Scan Date:        {data['metadata']['scan_date']}")
        output.append(f"Target System:    {data['metadata']['target_os'].get('platform', 'Unknown')} {data['metadata']['target_os'].get('version', '')}")
        output.append(f"Current User:     {data['metadata']['current_user'].get('user', 'Unknown')} ({data['metadata']['current_user'].get('level', 'Unknown')})")
        output.append(f"Framework:        {data['metadata']['framework']}")
        output.append("")
        
        # Risk Assessment
        output.append("🎯 RISK ASSESSMENT")
        output.append("─" * 50)
        output.append(f"Overall Risk Score: {data['metadata']['overall_risk_score']}/10.0")
        output.append(f"Risk Level:         {data['metadata']['risk_level']}")
        output.append(f"Total Findings:     {data['metadata']['total_findings']}")
        if data['metadata']['exploit_suggestions_count'] > 0:
            output.append(f"Exploit Suggestions: {data['metadata']['exploit_suggestions_count']}")
        output.append("")
        
        # Summary
        output.append("📈 FINDINGS SUMMARY")
        output.append("─" * 50)
        output.append(f"🔴 Critical:  {data['summary']['critical']:2d}")
        output.append(f"🟡 High:      {data['summary']['high']:2d}")
        output.append(f"🔵 Medium:    {data['summary']['medium']:2d}")
        output.append(f"🟢 Low:       {data['summary']['low']:2d}")
        output.append("")
        
        # Detailed Findings
        if data['findings']:
            output.append("🔍 DETAILED FINDINGS")
            output.append("═" * 70)
            
            # Group by severity
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                severity_findings = [f for f in data['findings'] if f['severity'] == severity]
                if severity_findings:
                    severity_icons = {'Critical': '🔴', 'High': '🟡', 'Medium': '🔵', 'Low': '🟢'}
                    output.append(f"\n{severity_icons[severity]} {severity.upper()} SEVERITY FINDINGS")
                    output.append("─" * 50)
                    
                    for finding in severity_findings:
                        output.append(f"\n[{finding['id']:02d}] {finding['description']}")
                        output.append(f"     Type: {finding['type'].title()}")
                        output.append(f"     MITRE ATT&CK: {finding['mitre_attack']['technique_id']} - {finding['mitre_attack']['technique_name']}")
                        output.append(f"     Risk Score: {finding['risk_score']}/10.0")
                        
                        if finding['details']:
                            output.append(f"     Details: {str(finding['details'])[:100]}...")
                        
                        if finding['mitigation']:
                            output.append(f"     💡 Mitigation: {finding['mitigation']}")
        
        # Exploit Suggestions
        if data.get('exploit_suggestions'):
            output.append("\n\n🎯 EXPLOIT SUGGESTIONS")
            output.append("═" * 70)
            output.append("⚠️  WARNING: Use only for authorized testing!")
            output.append("")
            
            for i, exploit in enumerate(data['exploit_suggestions'], 1):
                output.append(f"[{i:02d}] {exploit.get('name', 'Unknown').upper()}")
                output.append(f"     Severity: {exploit.get('severity', 'Unknown')}")
                output.append(f"     Description: {exploit.get('description', 'No description')}")
                
                if 'cve' in exploit:
                    output.append(f"     CVE: {exploit['cve']}")
                
                if 'command' in exploit:
                    output.append(f"     Command: {exploit['command']}")
                
                if 'exploit_url' in exploit:
                    output.append(f"     Exploit Code: {exploit['exploit_url']}")
                
                output.append("")
        
        if not data['findings']:
            output.append("✅ NO VULNERABILITIES FOUND")
            output.append("─" * 50)
            output.append("The system appears to be properly configured with no obvious")
            output.append("privilege escalation vulnerabilities detected.")
        
        output.append("\n" + "═" * 70)
        output.append("Report generated by PrivEsc-Framework v2.0")
        output.append("Enhanced with container detection, network analysis, and exploit suggestions")
        
        report_text = "\n".join(output)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"\n{self.colors['bold']}Text report saved:{self.colors['reset']} {output_file}")
        else:
            print(report_text)