"""Data normalization and cleaning"""

import re
from typing import List, Dict, Any
from datetime import datetime
from ..collectors.data_sources import VulnerabilityReport


class DataNormalizer:
    """Normalize and clean vulnerability report data"""
    
    def __init__(self):
        self.cleaned_count = 0
        self.removed_count = 0
    
    def normalize_reports(self, reports: List[VulnerabilityReport]) -> List[VulnerabilityReport]:
        """
        Normalize a list of vulnerability reports
        
        Args:
            reports: List of raw reports
            
        Returns:
            List of cleaned and normalized reports
        """
        
        normalized = []
        
        for report in reports:
            try:
                normalized_report = self.normalize_report(report)
                if normalized_report:
                    normalized.append(normalized_report)
                    self.cleaned_count += 1
                else:
                    self.removed_count += 1
            except Exception as e:
                print(f"Error normalizing report {getattr(report, 'report_id', 'unknown')}: {e}")
                self.removed_count += 1
        
        print(f"Normalized {self.cleaned_count} reports, removed {self.removed_count} invalid reports")
        
        return normalized
    
    def normalize(self, reports: List[VulnerabilityReport]) -> List[VulnerabilityReport]:
        """Alias for normalize_reports - for compatibility with TrainingPipeline"""
        return self.normalize_reports(reports)
    
    def normalize_report(self, report: VulnerabilityReport) -> VulnerabilityReport:
        """Normalize a single report"""
        
        # Skip if missing critical fields
        has_title = hasattr(report, 'title') and report.title
        has_description = hasattr(report, 'description') and report.description
        
        if not has_title and not has_description:
            return None
        
        if not hasattr(report, 'vulnerability_type') or not report.vulnerability_type:
            return None
        
        # Clean text fields
        if hasattr(report, 'title') and report.title:
            report.title = self.clean_text(report.title)
        
        if hasattr(report, 'description') and report.description:
            report.description = self.clean_text(report.description)
        
        # Normalize severity
        if hasattr(report, 'severity') and report.severity:
            report.severity = report.severity.lower().strip()
            if report.severity not in ['critical', 'high', 'medium', 'low', 'none']:
                report.severity = 'none'
        else:
            report.severity = 'none'
        
        # Ensure bounty is numeric
        if hasattr(report, 'bounty_amount') and report.bounty_amount:
            try:
                report.bounty_amount = float(report.bounty_amount)
            except:
                report.bounty_amount = 0.0
        else:
            report.bounty_amount = 0.0
        
        # Ensure CVSS score is present
        if not hasattr(report, 'cvss_score') or report.cvss_score is None:
            report.cvss_score = self._estimate_cvss_from_severity(report.severity)
        
        # Ensure technology stack is a list
        if not hasattr(report, 'technology_stack') or not report.technology_stack:
            report.technology_stack = []
        
        # Ensure tags is a list
        if not hasattr(report, 'tags') or not report.tags:
            report.tags = []
        
        # Ensure other fields have defaults
        if not hasattr(report, 'authentication_required'):
            report.authentication_required = False
        
        if not hasattr(report, 'user_interaction'):
            report.user_interaction = False
        
        if not hasattr(report, 'complexity'):
            report.complexity = 'medium'
        
        if not hasattr(report, 'privileges_required'):
            report.privileges_required = 'none'
        
        return report
    
    def clean_text(self, text: str) -> str:
        """Clean and normalize text"""
        
        if not text:
            return ""
        
        # Convert to string if not already
        text = str(text)
        
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        
        # Remove null bytes
        text = text.replace('\x00', '')
        
        # Trim
        text = text.strip()
        
        return text
    
    def _estimate_cvss_from_severity(self, severity: str) -> float:
        """Estimate CVSS score from severity rating"""
        severity_map = {
            'critical': 9.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 3.0,
            'none': 0.0
        }
        return severity_map.get(severity.lower(), 0.0)
