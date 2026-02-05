"""Data enricher for vulnerability reports"""

from typing import List
from ..collectors.data_sources import VulnerabilityReport


class Enricher:
    """Enrich vulnerability reports with additional computed fields"""
    
    def __init__(self):
        """Initialize the enricher"""
        pass
    
    def enrich_reports(self, reports: List[VulnerabilityReport]) -> List[VulnerabilityReport]:
        """
        Enrich a list of vulnerability reports
        
        Args:
            reports: List of VulnerabilityReport objects
            
        Returns:
            List of enriched reports
        """
        enriched = []
        
        for report in reports:
            enriched_report = self.enrich_report(report)
            enriched.append(enriched_report)
        
        return enriched
    
    def enrich(self, reports: List[VulnerabilityReport]) -> List[VulnerabilityReport]:
        """
        Alias for enrich_reports for compatibility
        
        Args:
            reports: List of VulnerabilityReport objects
            
        Returns:
            List of enriched reports
        """
        return self.enrich_reports(reports)
    
    def enrich_report(self, report: VulnerabilityReport) -> VulnerabilityReport:
        """
        Enrich a single vulnerability report with computed fields
        
        Args:
            report: VulnerabilityReport object
            
        Returns:
            Enriched VulnerabilityReport
        """
        # Calculate risk score
        report.risk_score = self.calculate_risk_score(report)
        
        # Calculate exploitability score
        report.exploitability_score = self.calculate_exploitability(report)
        
        # Calculate impact score
        report.impact_score = self.calculate_impact(report)
        
        # Calculate quality score
        report.quality_score = self.calculate_quality_score(report)
        
        # Add OWASP category if not present
        if not hasattr(report, 'owasp_category') or not report.owasp_category:
            report.owasp_category = self._infer_owasp_category(report)
        
        # Add CWE ID if not present
        if not hasattr(report, 'cwe_id') or not report.cwe_id:
            report.cwe_id = self._infer_cwe_id(report)
        
        return report
    
    def calculate_risk_score(self, report: VulnerabilityReport) -> float:
        """
        Calculate overall risk score (0-10)
        
        Args:
            report: VulnerabilityReport object
            
        Returns:
            Risk score from 0 to 10
        """
        # Base score from severity
        severity_scores = {
            'critical': 9.0,
            'high': 7.0,
            'medium': 5.0,
            'low': 3.0,
            'none': 1.0
        }
        
        severity = getattr(report, 'severity', 'medium').lower()
        base_score = severity_scores.get(severity, 5.0)
        
        # Adjust based on bounty amount
        bounty = getattr(report, 'bounty_amount', 0)
        if bounty > 10000:
            base_score += 1.0
        elif bounty > 5000:
            base_score += 0.5
        
        # Cap at 10
        return min(base_score, 10.0)
    
    def calculate_exploitability(self, report: VulnerabilityReport) -> float:
        """
        Calculate exploitability score (0-10)
        
        Args:
            report: VulnerabilityReport object
            
        Returns:
            Exploitability score from 0 to 10
        """
        score = 5.0  # Base score
        
        # Authentication required reduces exploitability
        if getattr(report, 'authentication_required', False):
            score -= 2.0
        
        # User interaction required reduces exploitability
        if getattr(report, 'user_interaction', False):
            score -= 1.5
        
        # Complexity affects exploitability
        complexity = getattr(report, 'complexity', 'medium')
        if complexity == 'low':
            score += 2.0
        elif complexity == 'high':
            score -= 2.0
        
        # Privileges required reduces exploitability
        privileges = getattr(report, 'privileges_required', 'none')
        if privileges == 'admin':
            score -= 3.0
        elif privileges == 'user':
            score -= 1.0
        
        # Ensure score is within bounds
        return max(0.0, min(score, 10.0))
    
    def calculate_impact(self, report: VulnerabilityReport) -> float:
        """
        Calculate impact score (0-10)
        
        Args:
            report: VulnerabilityReport object
            
        Returns:
            Impact score from 0 to 10
        """
        # Use CVSS score if available
        cvss = getattr(report, 'cvss_score', None)
        if cvss:
            return min(cvss, 10.0)
        
        # Otherwise estimate from severity
        severity_impacts = {
            'critical': 9.5,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'none': 0.5
        }
        
        severity = getattr(report, 'severity', 'medium').lower()
        return severity_impacts.get(severity, 5.0)
    
    def calculate_quality_score(self, report: VulnerabilityReport) -> float:
        """
        Calculate report quality score (0-1)
        
        Args:
            report: VulnerabilityReport object
            
        Returns:
            Quality score from 0 to 1
        """
        score = 0.0
        
        # Title exists and is substantial
        title = getattr(report, 'title', '')
        if title and len(title) > 10:
            score += 0.2
        
        # Description exists and is substantial
        description = getattr(report, 'description', '')
        if description and len(description) > 50:
            score += 0.3
        elif description and len(description) > 20:
            score += 0.15
        
        # Vulnerability type is specified
        vuln_type = getattr(report, 'vulnerability_type', '')
        if vuln_type and vuln_type != 'Unknown':
            score += 0.2
        
        # Severity is specified
        severity = getattr(report, 'severity', '')
        if severity and severity != 'none':
            score += 0.15
        
        # Has bounty information
        bounty = getattr(report, 'bounty_amount', 0)
        if bounty > 0:
            score += 0.15
        
        return min(score, 1.0)
    
    def _infer_owasp_category(self, report: VulnerabilityReport) -> str:
        """
        Infer OWASP Top 10 category from vulnerability type
        
        Args:
            report: VulnerabilityReport object
            
        Returns:
            OWASP category string
        """
        vuln_type = getattr(report, 'vulnerability_type', '').lower()
        
        owasp_mapping = {
            'sql injection': 'A03:2021-Injection',
            'xss': 'A03:2021-Injection',
            'cross-site scripting': 'A03:2021-Injection',
            'authentication bypass': 'A07:2021-Identification and Authentication Failures',
            'broken authentication': 'A07:2021-Identification and Authentication Failures',
            'idor': 'A01:2021-Broken Access Control',
            'broken access control': 'A01:2021-Broken Access Control',
            'csrf': 'A01:2021-Broken Access Control',
            'ssrf': 'A10:2021-Server-Side Request Forgery',
            'xxe': 'A05:2021-Security Misconfiguration',
            'rce': 'A03:2021-Injection',
            'remote code execution': 'A03:2021-Injection',
            'path traversal': 'A01:2021-Broken Access Control',
            'information disclosure': 'A01:2021-Broken Access Control',
        }
        
        for key, category in owasp_mapping.items():
            if key in vuln_type:
                return category
        
        return 'A06:2021-Vulnerable and Outdated Components'
    
    def _infer_cwe_id(self, report: VulnerabilityReport) -> str:
        """
        Infer CWE ID from vulnerability type
        
        Args:
            report: VulnerabilityReport object
            
        Returns:
            CWE ID string
        """
        vuln_type = getattr(report, 'vulnerability_type', '').lower()
        
        cwe_mapping = {
            'sql injection': 'CWE-89',
            'xss': 'CWE-79',
            'cross-site scripting': 'CWE-79',
            'csrf': 'CWE-352',
            'idor': 'CWE-639',
            'ssrf': 'CWE-918',
            'xxe': 'CWE-611',
            'rce': 'CWE-94',
            'remote code execution': 'CWE-94',
            'path traversal': 'CWE-22',
            'authentication bypass': 'CWE-287',
            'information disclosure': 'CWE-200',
        }
        
        for key, cwe in cwe_mapping.items():
            if key in vuln_type:
                return cwe
        
        return 'CWE-000'


# Alias for backward compatibility
class DataEnricher(Enricher):
    """Alias for Enricher class for backward compatibility"""
    pass
