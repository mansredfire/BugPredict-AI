"""Nuclei template generator for BugPredict AI"""

import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime


class NucleiTemplateGenerator:
    """Generate custom Nuclei YAML templates from vulnerability predictions"""
    
    def __init__(self, output_dir: str = "nuclei-templates/custom"):
        """
        Initialize the template generator
        
        Args:
            output_dir: Directory to save generated templates
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Template metadata
        self.author = "BugPredict-AI"
        self.version = "1.0"
        
        # Severity mapping
        self.severity_map = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'info'
        }
        
        # Template generators for each vulnerability type
        self.template_builders = {
            'SQL Injection': self._build_sqli_template,
            'XSS': self._build_xss_template,
            'Cross-Site Scripting': self._build_xss_template,
            'SSRF': self._build_ssrf_template,
            'IDOR': self._build_idor_template,
            'CSRF': self._build_csrf_template,
            'Authentication Bypass': self._build_auth_bypass_template,
            'RCE': self._build_rce_template,
            'Remote Code Execution': self._build_rce_template,
            'XXE': self._build_xxe_template,
            'Path Traversal': self._build_path_traversal_template,
            'Information Disclosure': self._build_info_disclosure_template,
        }
    
    def generate_template(
        self, 
        vulnerability_type: str, 
        target_info: Dict[str, Any],
        severity: str = 'medium',
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Generate a Nuclei template for a specific vulnerability type
        
        Args:
            vulnerability_type: Type of vulnerability
            target_info: Information about the target
            severity: Severity level
            metadata: Additional metadata
            
        Returns:
            Path to the generated template file
        """
        
        # Get the appropriate template builder
        builder = self.template_builders.get(
            vulnerability_type,
            self._build_generic_template
        )
        
        # Build the template
        template = builder(target_info, severity, metadata or {})
        
        # Generate filename
        safe_vuln_type = vulnerability_type.lower().replace(' ', '-')
        domain = target_info.get('domain', 'unknown').replace('.', '-')
        timestamp = datetime.now().strftime('%Y%m%d')
        filename = f"{safe_vuln_type}-{domain}-{timestamp}.yaml"
        
        # Save template
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            yaml.dump(template, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        return str(filepath)
    
    def _build_base_template(
        self,
        id_suffix: str,
        name: str,
        severity: str,
        description: str,
        tags: List[str]
    ) -> Dict:
        """Build base template structure"""
        
        template_id = f"bugpredict-{id_suffix}"
        
        return {
            'id': template_id,
            'info': {
                'name': name,
                'author': self.author,
                'severity': self.severity_map.get(severity.lower(), 'medium'),
                'description': description,
                'tags': tags,
                'classification': {
                    'cvss-metrics': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                    'cvss-score': 9.8,
                    'cwe-id': 'CWE-89'
                }
            },
            'http': []
        }
    
    def _build_sqli_template(
        self, 
        target_info: Dict, 
        severity: str, 
        metadata: Dict
    ) -> Dict:
        """Build SQL Injection template"""
        
        domain = target_info.get('domain', 'target.com')
        
        template = self._build_base_template(
            id_suffix='sqli',
            name=f'SQL Injection Detection - {domain}',
            severity=severity,
            description=f'Detects potential SQL injection vulnerabilities in {domain}',
            tags=['sqli', 'injection', 'bugpredict']
        )
        
        template['info']['classification']['cwe-id'] = 'CWE-89'
        
        # SQL injection payloads
        template['http'] = [{
            'method': 'GET',
            'path': [
                "{{BaseURL}}/?id=1'",
                "{{BaseURL}}/?id=1' OR '1'='1",
                "{{BaseURL}}/?id=1' AND 1=1--",
                "{{BaseURL}}/?id=1' UNION SELECT NULL--",
                "{{BaseURL}}/?search=' OR 1=1--"
            ],
            'matchers-condition': 'or',
            'matchers': [
                {
                    'type': 'word',
                    'words': [
                        'SQL syntax',
                        'mysql_fetch',
                        'PostgreSQL',
                        'ORA-01756',
                        'Microsoft OLE DB Provider',
                        'Unclosed quotation mark'
                    ],
                    'part': 'body'
                },
                {
                    'type': 'regex',
                    'regex': [
                        'SQL.*error',
                        'MySQLSyntaxErrorException',
                        'valid MySQL result'
                    ],
                    'part': 'body'
                }
            ]
        }]
        
        return template
    
    def _build_xss_template(
        self, 
        target_info: Dict, 
        severity: str, 
        metadata: Dict
    ) -> Dict:
        """Build XSS template"""
        
        domain = target_info.get('domain', 'target.com')
        
        template = self._build_base_template(
            id_suffix='xss',
            name=f'Cross-Site Scripting (XSS) - {domain}',
            severity=severity,
            description=f'Detects XSS vulnerabilities in {domain}',
            tags=['xss', 'injection', 'bugpredict']
        )
        
        template['info']['classification']['cwe-id'] = 'CWE-79'
        
        template['http'] = [{
            'method': 'GET',
            'path': [
                "{{BaseURL}}/?q=<script>alert('XSS')</script>",
                "{{BaseURL}}/?search=<img src=x onerror=alert(1)>",
                "{{BaseURL}}/?name=<svg/onload=alert(1)>",
                "{{BaseURL}}/?input='><script>alert(String.fromCharCode(88,83,83))</script>"
            ],
            'matchers': [
                {
                    'type': 'word',
                    'words': [
                        "<script>alert('XSS')</script>",
                        '<img src=x onerror=alert(1)>',
                        '<svg/onload=alert(1)>'
                    ],
                    'part': 'body'
                }
            ]
        }]
        
        return template
    
    def _build_ssrf_template(
        self, 
        target_info: Dict, 
        severity: str, 
        metadata: Dict
    ) -> Dict:
        """Build SSRF template"""
        
        domain = target_info.get('domain', 'target.com')
        
        template = self._build_base_template(
            id_suffix='ssrf',
            name=f'Server-Side Request Forgery (SSRF) - {domain}',
            severity=severity,
            description=f'Detects SSRF vulnerabilities in {domain}',
            tags=['ssrf', 'injection', 'bugpredict']
        )
        
        template['info']['classification']['cwe-id'] = 'CWE-918'
        
        template['http'] = [{
            'method': 'GET',
            'path': [
                "{{BaseURL}}/?url=http://127.0.0.1",
                "{{BaseURL}}/?url=http://localhost",
                "{{BaseURL}}/?url=http://169.254.169.254/latest/meta-data/",
                "{{BaseURL}}/?redirect=http://internal-service",
                "{{BaseURL}}/fetch?url=file:///etc/passwd"
            ],
            'matchers-condition': 'or',
            'matchers': [
                {
                    'type': 'word',
                    'words': [
                        'root:',
                        'ami-id',
                        'instance-id',
                        'localhost'
                    ],
                    'part': 'body'
                },
                {
                    'type': 'status',
                    'status': [200]
                }
            ]
        }]
        
        return template
    
    def _build_idor_template(
        self, 
        target_info: Dict, 
        severity: str, 
        metadata: Dict
    ) -> Dict:
        """Build IDOR template"""
        
        domain = target_info.get('domain', 'target.com')
        
        template = self._build_base_template(
            id_suffix='idor',
            name=f'Insecure Direct Object Reference (IDOR) - {domain}',
            severity=severity,
            description=f'Detects IDOR vulnerabilities in {domain}',
            tags=['idor', 'access-control', 'bugpredict']
        )
        
        template['info']['classification']['cwe-id'] = 'CWE-639'
        
        template['http'] = [{
            'method': 'GET',
            'path': [
                "{{BaseURL}}/api/user/1",
                "{{BaseURL}}/api/user/2",
                "{{BaseURL}}/profile?id=1",
                "{{BaseURL}}/profile?id=2",
                "{{BaseURL}}/document/1",
                "{{BaseURL}}/order/123"
            ],
            'matchers': [
                {
                    'type': 'status',
                    'status': [200]
                },
                {
                    'type': 'word',
                    'words': [
                        'email',
                        'username',
                        'password',
                        'private'
                    ],
                    'part': 'body'
                }
            ]
        }]
        
        return template
    
    def _build_csrf_template(
        self, 
        target_info: Dict, 
        severity: str, 
        metadata: Dict
    ) -> Dict:
        """Build CSRF template"""
        
        domain = target_info.get('domain', 'target.com')
        
        template = self._build_base_template(
            id_suffix='csrf',
            name=f'Cross-Site Request Forgery (CSRF) - {domain}',
            severity=severity,
            description=f'Detects missing CSRF protections in {domain}',
            tags=['csrf', 'access-control', 'bugpredict']
        )
        
        template['info']['classification']['cwe-id'] = 'CWE-352'
        
        template['http'] = [{
            'method': 'POST',
            'path': [
                "{{BaseURL}}/api/profile/update",
                "{{BaseURL}}/api/password/change",
                "{{BaseURL}}/api/delete/account"
            ],
            'body': 'email=attacker@evil.com',
            'matchers': [
                {
                    'type': 'status',
                    'status': [200, 302]
                }
            ],
            'matchers-condition': 'and',
            'negative': True,
            'words': [
                'csrf',
                'token',
                '_token',
                'csrf_token',
                'anti-csrf'
            ]
        }]
        
        return template
    
    def _build_auth_bypass_template(
        self, 
        target_info: Dict, 
        severity: str, 
        metadata: Dict
    ) -> Dict:
        """Build Authentication Bypass template"""
        
        domain = target_info.get('domain', 'target.com')
        
        template = self._build_base_template(
            id_suffix='auth-bypass',
            name=f'Authentication Bypass - {domain}',
            severity=severity,
            description=f'Detects authentication bypass vulnerabilities in {domain}',
            tags=['auth', 'bypass', 'bugpredict']
        )
        
        template['info']['classification']['cwe-id'] = 'CWE-287'
        
        template['http'] = [{
            'method': 'GET',
            'path': [
                "{{BaseURL}}/admin",
                "{{BaseURL}}/admin/",
                "{{BaseURL}}/administrator",
                "{{BaseURL}}/api/admin",
                "{{BaseURL}}/../admin"
            ],
            'headers': {
                'X-Original-URL': '/admin',
                'X-Rewrite-URL': '/admin'
            },
            'matchers': [
                {
                    'type': 'status',
                    'status': [200]
                },
                {
                    'type': 'word',
                    'words': [
                        'admin',
                        'dashboard',
                        'panel'
                    ],
                    'part': 'body'
                }
            ]
        }]
        
        return template
    
    def _build_rce_template(
        self, 
        target_info: Dict, 
        severity: str, 
        metadata: Dict
    ) -> Dict:
        """Build RCE template"""
        
        domain = target_info.get('domain', 'target.com')
        
        template = self._build_base_template(
            id_suffix='rce',
            name=f'Remote Code Execution (RCE) - {domain}',
            severity=severity,
            description=f'Detects RCE vulnerabilities in {domain}',
            tags=['rce', 'injection', 'critical', 'bugpredict']
        )
        
        template['info']['classification']['cwe-id'] = 'CWE-94'
        
        template['http'] = [{
            'method': 'POST',
            'path': [
                "{{BaseURL}}/upload",
                "{{BaseURL}}/api/execute",
                "{{BaseURL}}/cmd"
            ],
            'body': 'cmd=whoami',
            'matchers': [
                {
                    'type': 'regex',
                    'regex': [
                        'root',
                        'administrator',
                        'uid=',
                        'gid='
                    ],
                    'part': 'body'
                }
            ]
        }]
        
        return template
    
    def _build_xxe_template(
        self, 
        target_info: Dict, 
        severity: str, 
        metadata: Dict
    ) -> Dict:
        """Build XXE template"""
        
        domain = target_info.get('domain', 'target.com')
        
        template = self._build_base_template(
            id_suffix='xxe',
            name=f'XML External Entity (XXE) - {domain}',
            severity=severity,
            description=f'Detects XXE vulnerabilities in {domain}',
            tags=['xxe', 'injection', 'bugpredict']
        )
        
        template['info']['classification']['cwe-id'] = 'CWE-611'
        
        xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>
    <data>&xxe;</data>
</root>'''
        
        template['http'] = [{
            'method': 'POST',
            'path': ["{{BaseURL}}/api/xml"],
            'headers': {
                'Content-Type': 'application/xml'
            },
            'body': xxe_payload,
            'matchers': [
                {
                    'type': 'word',
                    'words': [
                        'root:',
                        '/bin/bash',
                        '/bin/sh'
                    ],
                    'part': 'body'
                }
            ]
        }]
        
        return template
    
    def _build_path_traversal_template(
        self, 
        target_info: Dict, 
        severity: str, 
        metadata: Dict
    ) -> Dict:
        """Build Path Traversal template"""
        
        domain = target_info.get('domain', 'target.com')
        
        template = self._build_base_template(
            id_suffix='path-traversal',
            name=f'Path Traversal - {domain}',
            severity=severity,
            description=f'Detects path traversal vulnerabilities in {domain}',
            tags=['path-traversal', 'lfi', 'bugpredict']
        )
        
        template['info']['classification']['cwe-id'] = 'CWE-22'
        
        template['http'] = [{
            'method': 'GET',
            'path': [
                "{{BaseURL}}/download?file=../../../../etc/passwd",
                "{{BaseURL}}/file?path=..\\..\\..\\..\\windows\\win.ini",
                "{{BaseURL}}/?page=....//....//....//etc/passwd",
                "{{BaseURL}}/api/file?name=../../../../../../etc/hosts"
            ],
            'matchers': [
                {
                    'type': 'regex',
                    'regex': [
                        'root:.*:0:0:',
                        '\\[extensions\\]'
                    ],
                    'part': 'body'
                }
            ]
        }]
        
        return template
    
    def _build_info_disclosure_template(
        self, 
        target_info: Dict, 
        severity: str, 
        metadata: Dict
    ) -> Dict:
        """Build Information Disclosure template"""
        
        domain = target_info.get('domain', 'target.com')
        
        template = self._build_base_template(
            id_suffix='info-disclosure',
            name=f'Information Disclosure - {domain}',
            severity=severity,
            description=f'Detects information disclosure in {domain}',
            tags=['info-disclosure', 'exposure', 'bugpredict']
        )
        
        template['info']['classification']['cwe-id'] = 'CWE-200'
        
        template['http'] = [{
            'method': 'GET',
            'path': [
                "{{BaseURL}}/.git/config",
                "{{BaseURL}}/.env",
                "{{BaseURL}}/config.php",
                "{{BaseURL}}/.aws/credentials",
                "{{BaseURL}}/phpinfo.php",
                "{{BaseURL}}/server-status"
            ],
            'matchers-condition': 'or',
            'matchers': [
                {
                    'type': 'word',
                    'words': [
                        '[core]',
                        'DB_PASSWORD',
                        'aws_access_key',
                        'phpinfo()',
                        'Server Version'
                    ],
                    'part': 'body'
                },
                {
                    'type': 'status',
                    'status': [200]
                }
            ]
        }]
        
        return template
    
    def _build_generic_template(
        self, 
        target_info: Dict, 
        severity: str, 
        metadata: Dict
    ) -> Dict:
        """Build generic vulnerability template"""
        
        domain = target_info.get('domain', 'target.com')
        vuln_type = metadata.get('vulnerability_type', 'Generic Vulnerability')
        
        template = self._build_base_template(
            id_suffix='generic',
            name=f'{vuln_type} - {domain}',
            severity=severity,
            description=f'Detects {vuln_type} in {domain}',
            tags=['generic', 'bugpredict']
        )
        
        template['http'] = [{
            'method': 'GET',
            'path': ["{{BaseURL}}/"],
            'matchers': [
                {
                    'type': 'status',
                    'status': [200]
                }
            ]
        }]
        
        return template
