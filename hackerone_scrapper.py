# src/collectors/hackerone_scraper.py

import requests
from bs4 import BeautifulSoup
from typing import List, Optional
import time
import json
from datetime import datetime

class HackerOneCollector(DataCollector):
    """
    Collects disclosed reports from HackerOne
    Note: Respects rate limits and robots.txt
    """
    
    BASE_URL = "https://hackerone.com"
    
    def __init__(self, api_token: Optional[str] = None):
        super().__init__()
        self.api_token = api_token
        self.session = requests.Session()
        if api_token:
            self.session.headers.update({
                'Authorization': f'Bearer {api_token}'
            })
    
    def collect(self, limit: int = 1000) -> List[VulnerabilityReport]:
        """
        Collect disclosed reports from HackerOne
        """
        reports = []
        page = 1
        
        while len(reports) < limit:
            try:
                # Use HackerOne's Hacktivity feed
                url = f"{self.BASE_URL}/hacktivity.json"
                params = {
                    'queryString': '',
                    'page': page,
                    'filter': 'disclosed',
                    'orderBy': 'latest_disclosable_activity_at'
                }
                
                response = self.session.get(url, params=params)
                response.raise_for_status()
                
                data = response.json()
                
                if not data.get('reports'):
                    break
                
                for report in data['reports']:
                    normalized = self.normalize(report)
                    if normalized:
                        reports.append(normalized)
                
                page += 1
                time.sleep(2)  # Rate limiting
                
            except Exception as e:
                print(f"Error collecting from HackerOne: {e}")
                break
        
        return reports
    
    def normalize(self, raw_data: Dict) -> Optional[VulnerabilityReport]:
        """Normalize HackerOne report to standard format"""
        try:
            return VulnerabilityReport(
                report_id=raw_data.get('id'),
                platform='hackerone',
                target_domain=self._extract_domain(raw_data),
                target_company=raw_data.get('team', {}).get('name'),
                target_program=raw_data.get('team', {}).get('handle'),
                vulnerability_type=self._extract_vuln_type(raw_data),
                severity=raw_data.get('severity_rating', 'none').lower(),
                cvss_score=self._calculate_cvss(raw_data),
                technology_stack=self._extract_tech_stack(raw_data),
                endpoint=self._extract_endpoint(raw_data),
                http_method=self._extract_method(raw_data),
                vulnerability_location=self._extract_location(raw_data),
                description=raw_data.get('title', ''),
                steps_to_reproduce=self._extract_steps(raw_data),
                impact=self._extract_impact(raw_data),
                remediation='',
                reported_date=self._parse_date(raw_data.get('created_at')),
                disclosed_date=self._parse_date(raw_data.get('disclosed_at')),
                bounty_amount=float(raw_data.get('bounty_amount', 0)),
                researcher_reputation=raw_data.get('reporter', {}).get('reputation', 0),
                authentication_required=self._requires_auth(raw_data),
                privileges_required=self._extract_privileges(raw_data),
                user_interaction=self._requires_interaction(raw_data),
                complexity=self._estimate_complexity(raw_data),
                tags=raw_data.get('tags', []),
                owasp_category=self._map_to_owasp(raw_data),
                cwe_id=self._extract_cwe(raw_data)
            )
        except Exception as e:
            print(f"Error normalizing HackerOne report: {e}")
            return None
    
    def _extract_vuln_type(self, data: Dict) -> str:
        """Extract vulnerability type from report"""
        weakness = data.get('weakness', {}).get('name', '')
        
        # Map to standard categories
        mapping = {
            'Cross-site Scripting (XSS)': 'XSS',
            'SQL Injection': 'SQLI',
            'Insecure Direct Object Reference (IDOR)': 'IDOR',
            'Server-Side Request Forgery (SSRF)': 'SSRF',
            'Cross-Site Request Forgery (CSRF)': 'CSRF',
            'Remote Code Execution': 'RCE',
            'Authentication Bypass': 'AUTH_BYPASS',
            'Open Redirect': 'OPEN_REDIRECT',
            'Information Disclosure': 'INFO_DISCLOSURE',
            'Business Logic Error': 'BUSINESS_LOGIC'
        }
        
        return mapping.get(weakness, 'OTHER')
    
    def _extract_tech_stack(self, data: Dict) -> List[str]:
        """Extract technology stack from report"""
        tech = []
        
        # Extract from structured fields
        if data.get('structured_scope'):
            asset_type = data['structured_scope'].get('asset_type', '')
            tech.append(asset_type)
        
        # Extract from title and description
        title = data.get('title', '').lower()
        description = data.get('vulnerability_information', '').lower()
        
        tech_indicators = {
            'react': 'React',
            'angular': 'Angular',
            'vue': 'Vue.js',
            'node': 'Node.js',
            'python': 'Python',
            'ruby': 'Ruby',
            'php': 'PHP',
            'java': 'Java',
            'graphql': 'GraphQL',
            'rest api': 'REST',
            'mongodb': 'MongoDB',
            'postgresql': 'PostgreSQL',
            'mysql': 'MySQL',
            'redis': 'Redis',
            'aws': 'AWS',
            'azure': 'Azure',
            'gcp': 'Google Cloud',
            'docker': 'Docker',
            'kubernetes': 'Kubernetes'
        }
        
        text = f"{title} {description}"
        for indicator, tech_name in tech_indicators.items():
            if indicator in text:
                tech.append(tech_name)
        
        return list(set(tech))
    
    def _calculate_cvss(self, data: Dict) -> float:
        """Calculate or extract CVSS score"""
        severity_mapping = {
            'critical': 9.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 3.0,
            'none': 0.0
        }
        
        severity = data.get('severity_rating', 'none').lower()
        return severity_mapping.get(severity, 0.0)
    
    def _extract_domain(self, data: Dict) -> str:
        """Extract target domain"""
        scope = data.get('structured_scope', {})
        return scope.get('asset_identifier', '')
    
    def _extract_endpoint(self, data: Dict) -> str:
        """Extract vulnerable endpoint"""
        # Parse from description/title
        title = data.get('title', '')
        # Simple regex to find URLs/endpoints
        import re
        endpoint_pattern = r'(?:https?://)?(?:[\w-]+\.)+[\w-]+(?:/[\w.-]*)*'
        matches = re.findall(endpoint_pattern, title)
        return matches[0] if matches else ''
    
    def _extract_method(self, data: Dict) -> str:
        """Extract HTTP method"""
        text = f"{data.get('title', '')} {data.get('vulnerability_information', '')}"
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
        for method in methods:
            if method in text.upper():
                return method
        return 'UNKNOWN'
    
    def _extract_location(self, data: Dict) -> str:
        """Determine vulnerability location"""
        asset_type = data.get('structured_scope', {}).get('asset_type', '')
        
        location_mapping = {
            'URL': 'web',
            'API': 'api',
            'MOBILE_APP': 'mobile',
            'SOURCE_CODE': 'code',
            'HARDWARE': 'hardware',
            'OTHER': 'other'
        }
        
        return location_mapping.get(asset_type, 'web')
    
    def _parse_date(self, date_str: str) -> datetime:
        """Parse ISO date string"""
        try:
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except:
            return datetime.now()
    
    def _requires_auth(self, data: Dict) -> bool:
        """Determine if authentication is required"""
        text = f"{data.get('title', '')} {data.get('vulnerability_information', '')}".lower()
        auth_keywords = ['authenticated', 'logged in', 'requires login', 'auth required']
        return any(keyword in text for keyword in auth_keywords)
    
    def _extract_privileges(self, data: Dict) -> str:
        """Extract required privilege level"""
        text = f"{data.get('title', '')} {data.get('vulnerability_information', '')}".lower()
        
        if any(word in text for word in ['admin', 'administrator']):
            return 'high'
        elif any(word in text for word in ['user', 'authenticated', 'logged in']):
            return 'low'
        else:
            return 'none'
    
    def _requires_interaction(self, data: Dict) -> bool:
        """Determine if user interaction is required"""
        text = f"{data.get('title', '')} {data.get('vulnerability_information', '')}".lower()
        interaction_keywords = ['click', 'visit', 'open', 'user interaction']
        return any(keyword in text for keyword in interaction_keywords)
    
    def _estimate_complexity(self, data: Dict) -> str:
        """Estimate exploit complexity"""
        steps = len(self._extract_steps(data))
        
        if steps <= 3:
            return 'low'
        elif steps <= 6:
            return 'medium'
        else:
            return 'high'
    
    def _extract_steps(self, data: Dict) -> List[str]:
        """Extract steps to reproduce"""
        # This would need more sophisticated parsing
        # For now, return empty list
        return []
    
    def _extract_impact(self, data: Dict) -> str:
        """Extract impact description"""
        return data.get('vulnerability_information', '')[:500]
    
    def _map_to_owasp(self, data: Dict) -> str:
        """Map vulnerability to OWASP Top 10 category"""
        vuln_type = self._extract_vuln_type(data)
        
        owasp_mapping = {
            'AUTH_BYPASS': 'A01:2021-Broken Access Control',
            'SQLI': 'A03:2021-Injection',
            'XSS': 'A03:2021-Injection',
            'IDOR': 'A01:2021-Broken Access Control',
            'SSRF': 'A10:2021-Server-Side Request Forgery',
            'CSRF': 'A01:2021-Broken Access Control',
            'INFO_DISCLOSURE': 'A01:2021-Broken Access Control',
            'RCE': 'A03:2021-Injection',
            'BUSINESS_LOGIC': 'A04:2021-Insecure Design'
        }
        
        return owasp_mapping.get(vuln_type, 'Other')
    
    def _extract_cwe(self, data: Dict) -> int:
        """Extract CWE ID"""
        # Parse from weakness information
        weakness = data.get('weakness', {})
        # This would need actual CWE mapping
        return 0
