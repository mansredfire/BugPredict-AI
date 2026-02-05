#!/usr/bin/env python3
"""Create SQLite database with mock vulnerability data"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import random
import sqlite3
from datetime import datetime, timedelta

# Mock data
DOMAINS = ['example.com', 'test.io', 'demo.app', 'secure.net', 'webapp.com', 'api.example.com', 'shop.io', 'xml.app', 'files.net', 'info.com']
COMPANIES = ['Example Corp', 'Test Inc', 'Demo LLC', 'Secure Net', 'WebApp Inc', 'API Corp', 'Shop Inc', 'XML Corp', 'Files Inc', 'Info Corp']
VULN_TYPES = ['SQL Injection', 'XSS', 'SSRF', 'IDOR', 'CSRF', 'Authentication Bypass', 'RCE', 'XXE', 'Path Traversal', 'Information Disclosure']
SEVERITIES = ['critical', 'high', 'medium', 'low']
TECH_STACKS = [
    'React,Node.js,MySQL',
    'Angular,Java,PostgreSQL',
    'Vue.js,Python,MongoDB',
    'Django,PostgreSQL',
    'Flask,SQLite',
    'Express,Redis,MySQL',
    'Spring Boot,Oracle',
    'Laravel,MySQL',
    'Ruby on Rails,PostgreSQL',
    'ASP.NET,SQL Server'
]
ENDPOINTS = ['/api/login', '/api/users', '/api/data', '/admin', '/upload', '/search', '/api/comments', '/settings', '/download', '/api/auth']
HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']

def create_database(db_path: str, num_reports: int = 100):
    """Create SQLite database with mock vulnerability reports"""
    
    # Create database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerability_reports (
            report_id TEXT PRIMARY KEY,
            target_domain TEXT NOT NULL,
            target_company TEXT NOT NULL,
            vulnerability_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            cvss_score REAL NOT NULL,
            tech_stack TEXT,
            description TEXT,
            endpoint TEXT,
            http_method TEXT,
            bounty_amount REAL,
            auth_required INTEGER,
            complexity TEXT,
            reported_date TEXT,
            researcher_reputation INTEGER
        )
    ''')
    
    print(f"Creating {num_reports} mock vulnerability reports...")
    
    # Generate mock data
    for i in range(num_reports):
        report_id = f"VULN-{i+1:05d}"
        target_domain = random.choice(DOMAINS)
        target_company = random.choice(COMPANIES)
        vuln_type = random.choice(VULN_TYPES)
        severity = random.choice(SEVERITIES)
        
        # CVSS score based on severity
        cvss_ranges = {
            'critical': (9.0, 10.0),
            'high': (7.0, 8.9),
            'medium': (4.0, 6.9),
            'low': (0.1, 3.9)
        }
        cvss_score = round(random.uniform(*cvss_ranges[severity]), 1)
        
        tech_stack = random.choice(TECH_STACKS)
        description = f"{vuln_type} vulnerability found in {target_domain}"
        endpoint = random.choice(ENDPOINTS)
        http_method = random.choice(HTTP_METHODS)
        
        # Bounty amount based on severity
        bounty_ranges = {
            'critical': (2000, 5000),
            'high': (500, 2000),
            'medium': (200, 500),
            'low': (50, 200)
        }
        bounty_amount = random.randint(*bounty_ranges[severity])
        
        auth_required = random.choice([0, 1])
        complexity = random.choice(['low', 'medium', 'high'])
        
        # Random date within last year
        days_ago = random.randint(0, 365)
        reported_date = (datetime.now() - timedelta(days=days_ago)).strftime('%Y-%m-%d')
        
        researcher_reputation = random.randint(100, 10000)
        
        # Insert data
        cursor.execute('''
            INSERT INTO vulnerability_reports VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            report_id, target_domain, target_company, vuln_type, severity,
            cvss_score, tech_stack, description, endpoint, http_method,
            bounty_amount, auth_required, complexity, reported_date,
            researcher_reputation
        ))
    
    conn.commit()
    
    # Show summary
    cursor.execute('SELECT COUNT(*) FROM vulnerability_reports')
    total = cursor.fetchone()[0]
    
    cursor.execute('SELECT vulnerability_type, COUNT(*) as count FROM vulnerability_reports GROUP BY vulnerability_type ORDER BY count DESC')
    vuln_counts = cursor.fetchall()
    
    cursor.execute('SELECT severity, COUNT(*) as count FROM vulnerability_reports GROUP BY severity ORDER BY count DESC')
    severity_counts = cursor.fetchall()
    
    conn.close()
    
    print(f"\n✅ Created database: {db_path}")
    print(f"Total reports: {total}")
    print(f"\nVulnerability breakdown:")
    for vuln, count in vuln_counts:
        print(f"  {vuln:30} {count:3}")
    print(f"\nSeverity breakdown:")
    for sev, count in severity_counts:
        print(f"  {sev:10} {count:3}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Create mock vulnerability database')
    parser.add_argument('--output', '-o', default='data/mock_vulns.db', help='Output database file')
    parser.add_argument('--reports', '-r', type=int, default=100, help='Number of reports to generate')
    
    args = parser.parse_args()
    
    # Create data directory if needed
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    print("=" * 70)
    print("Mock Vulnerability Database Generator")
    print("=" * 70)
    print()
    
    create_database(str(output_path), args.reports)
    
    print()
    print("=" * 70)
    print("Next steps:")
    print(f"  1. View tables: python scripts/train_from_database.py --db 'sqlite:///{args.output}' --list-tables")
    print(f"  2. View schema: python scripts/train_from_database.py --db 'sqlite:///{args.output}' --schema vulnerability_reports")
    print(f"  3. Train models: python scripts/train_from_database.py --db 'sqlite:///{args.output}' --table vulnerability_reports")
    print("=" * 70)

if __name__ == '__main__':
    main()
