"""Enrich vulnerability reports with additional data"""

from typing import List
from ..collectors.data_sources import VulnerabilityReport


class DataEnricher:
    """Enrich vulnerability reports with derived data"""
    
    def enrich_reports(self, reports: List[VulnerabilityReport]) -> List[VulnerabilityReport]:
        """
        Enrich reports with additional computed fields
        
        Args:
            reports: List of reports to enrich
            
        Returns:
            List of enriched reports
        """
        
        for report in reports:
            report = self.enrich_report(report)
        
        return reports
    
    def enrich_report(self, report: VulnerabilityReport) -> VulnerabilityReport:
        """Enrich a single report"""
        
        # Add risk score based on severity and bounty
        report.risk_score = self.calculate_risk_score(report)
        
        # Add exploitability score
        report.exploitability_score = self.calculate_exploitability(report)
        
        return report
    
    def calculate_risk_score(self, report: VulnerabilityReport) -> float:
        """Calculate overall risk score"""
        
        severity_scores = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'none': 0.0
        }
        
        base_score = severity_scores.get(report.severity, 0.0)
        
        # Adjust based on bounty (indicator of real-world value)
        if report.bounty_amount:
            bounty_factor = min(report.bounty_amount / 10000, 2.0)
            base_score *= (1 + bounty_factor * 0.2)
        
        return min(base_score, 10.0)
    
    def calculate_exploitability(self, report: VulnerabilityReport) -> float:
        """Calculate exploitability score"""
        
        score = 5.0  # Base score
        
        # Authentication required reduces exploitability
        if not report.authentication_required:
            score += 2.0
        
        # User interaction reduces exploitability
        if not report.user_interaction:
            score += 1.0
        
        # Complexity affects exploitability
        complexity_factors = {
            'low': 2.0,
            'medium': 0.0,
            'high': -2.0
        }
        score += complexity_factors.get(report.complexity, 0.0)
        
        return max(0.0, min(score, 10.0))
