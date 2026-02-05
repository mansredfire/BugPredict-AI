"""CSV importer for vulnerability reports"""

import pandas as pd
from typing import List
from pathlib import Path
from datetime import datetime

from .data_sources import VulnerabilityReport


class CSVImporter:
    """Import vulnerability reports from CSV files"""
    
    def __init__(self):
        self.reports = []
    
    def import_from_csv(self, filepath: str) -> List[VulnerabilityReport]:
        """
        Import vulnerability reports from CSV file
        
        Args:
            filepath: Path to CSV file
            
        Returns:
            List of VulnerabilityReport objects
            
        Expected CSV columns:
            - report_id (required)
            - target_domain (required)
            - target_company (required)
            - vulnerability_type (required)
            - severity (required)
            - cvss_score (required)
            - tech_stack (comma-separated, optional)
            - description (optional)
            - target_program (optional)
            - bounty_amount (optional)
            - endpoint (optional)
            - http_method (optional)
        """
        
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise FileNotFoundError(f"CSV file not found: {filepath}")
        
        print(f"Loading CSV from: {filepath}")
        
        # Read CSV
        df = pd.read_csv(filepath)
        
        # Validate required columns
        required_cols = [
            'report_id', 'target_domain', 'target_company',
            'vulnerability_type', 'severity', 'cvss_score'
        ]
        
        missing_cols = [col for col in required_cols if col not in df.columns]
        if missing_cols:
            raise ValueError(f"Missing required columns: {missing_cols}")
        
        reports = []
        
        for idx, row in df.iterrows():
            try:
                # Parse tech stack
                tech_stack = []
                if 'tech_stack' in df.columns and pd.notna(row.get('tech_stack')):
                    tech_stack = [t.strip() for t in str(row['tech_stack']).split(',')]
                
                # Create report
                report = VulnerabilityReport(
                    report_id=str(row['report_id']),
                    platform='csv_import',
                    target_domain=str(row['target_domain']),
                    target_company=str(row['target_company']),
                    target_program=str(row.get('target_program', row['target_company'])),
                    vulnerability_type=str(row['vulnerability_type']),
                    severity=str(row['severity']).lower(),
                    cvss_score=float(row['cvss_score']),
                    technology_stack=tech_stack,
                    endpoint=str(row.get('endpoint', '/')),
                    http_method=str(row.get('http_method', 'GET')),
                    vulnerability_location='web',
                    description=str(row.get('description', '')),
                    steps_to_reproduce=[],
                    impact=str(row.get('impact', '')),
                    remediation=str(row.get('remediation', '')),
                    reported_date=None,
                    disclosed_date=None,
                    bounty_amount=float(row.get('bounty_amount', 0.0)),
                    researcher_reputation=int(row.get('researcher_reputation', 0)),
                    authentication_required=bool(row.get('auth_required', False)),
                    privileges_required=str(row.get('privileges_required', 'none')),
                    user_interaction=bool(row.get('user_interaction', False)),
                    complexity=str(row.get('complexity', 'medium')),
                    tags=[],
                    owasp_category=str(row.get('owasp_category', '')),
                    cwe_id=int(row.get('cwe_id', 0)),
                    raw_data={}
                )
                
                reports.append(report)
                
            except Exception as e:
                print(f"Warning: Skipping row {idx} due to error: {e}")
                continue
        
        print(f"✓ Imported {len(reports)} reports from CSV")
        self.reports = reports
        return reports
    
    def validate_csv(self, filepath: str) -> dict:
        """
        Validate CSV file without importing
        
        Returns:
            Dictionary with validation results
        """
        filepath = Path(filepath)
        
        if not filepath.exists():
            return {'valid': False, 'error': 'File not found'}
        
        try:
            df = pd.read_csv(filepath)
            
            required_cols = [
                'report_id', 'target_domain', 'target_company',
                'vulnerability_type', 'severity', 'cvss_score'
            ]
            
            missing_cols = [col for col in required_cols if col not in df.columns]
            
            if missing_cols:
                return {
                    'valid': False,
                    'error': f'Missing columns: {missing_cols}',
                    'found_columns': list(df.columns)
                }
            
            # Check for empty required fields
            empty_fields = []
            for col in required_cols:
                if df[col].isna().any():
                    empty_fields.append(col)
            
            if empty_fields:
                return {
                    'valid': False,
                    'error': f'Empty values in required columns: {empty_fields}',
                    'rows': len(df)
                }
            
            return {
                'valid': True,
                'rows': len(df),
                'columns': list(df.columns),
                'required_columns_present': True
            }
            
        except Exception as e:
            return {'valid': False, 'error': str(e)}
