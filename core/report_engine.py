"""
Report Engine Module
Generates reports with risk scoring and MITRE ATT&CK mapping
"""

import json
import yaml
from datetime import datetime
from pathlib import Path

class ReportEngine:
    def __init__(self):
        self.mitre_mapping = {
            'T1068': 'Exploitation for Privilege Escalation',
            'T1548': 'Abuse Elevation Control Mechanism',
            'T1053': 'Scheduled Task/Job',
            'T1574': 'Hijack Execution Flow',
            'T1055': 'Process Injection',
            'T1134': 'Access Token Manipulation'
        }
        
        self.risk_scores = {
            'Critical': 9.0,
            'High': 7.0,
            'Medium': 5.0,
            'Low': 3.0
        }
    
    def calculate_risk_score(self, findings):
        """Calculate overall risk score"""
        if not findings:
            return 0.0
        
        total_score = sum(self.risk_scores.get(f.get('severity', 'Low'), 3.0) for f in findings)
        return min(total_score / len(findings), 10.0)
    
    def classify_severity(self, finding_type, details):
        """Classify finding severity based on type and details"""
        critical_indicators = ['root', 'administrator', 'system', 'suid', 'setuid']
        high_indicators = ['sudo', 'admin', 'service', 'cron', 'scheduled']
        
        description = details.get('description', '').lower()
        
        if any(indicator in description for indicator in critical_indicators):
            return 'Critical'
        elif any(indicator in description for indicator in high_indicators):
            return 'High'
        elif 'writable' in description or 'permission' in description:
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
            'scheduled_task': 'T1053.005'
        }
        return mapping.get(finding_type.lower(), 'T1068')
    
    def generate_report(self, findings, os_info, priv_info, output_format='json', output_file=None):
        """Generate comprehensive report"""
        # Process findings
        processed_findings = []
        for finding in findings:
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
        
        # Generate report data
        report_data = {
            'metadata': {
                'framework': 'PrivEsc-Framework v1.0',
                'scan_date': datetime.now().isoformat(),
                'target_os': os_info,
                'current_user': priv_info,
                'total_findings': len(processed_findings),
                'overall_risk_score': self.calculate_risk_score(processed_findings)
            },
            'summary': {
                'critical': len([f for f in processed_findings if f['severity'] == 'Critical']),
                'high': len([f for f in processed_findings if f['severity'] == 'High']),
                'medium': len([f for f in processed_findings if f['severity'] == 'Medium']),
                'low': len([f for f in processed_findings if f['severity'] == 'Low'])
            },
            'findings': processed_findings
        }
        
        # Output report
        if output_format == 'json':
            self._output_json(report_data, output_file)
        elif output_format == 'txt':
            self._output_txt(report_data, output_file)
        
        print(f"\n[+] Report generated: {output_file or 'console'}")
        print(f"[+] Overall Risk Score: {report_data['metadata']['overall_risk_score']:.1f}/10.0")
    
    def _output_json(self, data, output_file):
        """Output JSON format"""
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
        else:
            print(json.dumps(data, indent=2))
    
    def _output_txt(self, data, output_file):
        """Output human-readable text format"""
        output = []
        output.append("=" * 70)
        output.append("PRIVESC-FRAMEWORK ENUMERATION REPORT")
        output.append("=" * 70)
        output.append(f"Scan Date: {data['metadata']['scan_date']}")
        output.append(f"Target OS: {data['metadata']['target_os']['platform']}")
        output.append(f"Current User: {data['metadata']['current_user']['user']}")
        output.append(f"Overall Risk Score: {data['metadata']['overall_risk_score']:.1f}/10.0")
        output.append("")
        
        output.append("SUMMARY:")
        output.append(f"  Critical: {data['summary']['critical']}")
        output.append(f"  High: {data['summary']['high']}")
        output.append(f"  Medium: {data['summary']['medium']}")
        output.append(f"  Low: {data['summary']['low']}")
        output.append("")
        
        output.append("FINDINGS:")
        output.append("-" * 70)
        
        for finding in data['findings']:
            output.append(f"[{finding['id']}] {finding['severity']} - {finding['type']}")
            output.append(f"    Description: {finding['description']}")
            output.append(f"    MITRE ATT&CK: {finding['mitre_attack']['technique_id']} - {finding['mitre_attack']['technique_name']}")
            output.append(f"    Risk Score: {finding['risk_score']}")
            if finding['mitigation']:
                output.append(f"    Mitigation: {finding['mitigation']}")
            output.append("")
        
        report_text = "\n".join(output)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_text)
        else:
            print(report_text)