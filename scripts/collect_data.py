#!/usr/bin/env python3
"""
Data collection script
Collects vulnerability data from HackerOne, Bugcrowd, and NVD
"""

import argparse
from datetime import datetime, timedelta
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.collectors.hackerone_scraper import HackerOneCollector
from src.collectors.bugcrowd_scraper import BugcrowdCollector
from src.collectors.cve_collector import CVECollector


def main():
    parser = argparse.ArgumentParser(description='Collect vulnerability data')
    
    parser.add_argument(
        '--source',
        choices=['hackerone', 'bugcrowd', 'cve', 'all'],
        default='all',
        help='Data source to collect from'
    )
    
    parser.add_argument(
        '--limit',
        type=int,
        default=1000,
        help='Maximum number of reports to collect'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        default='data/raw',
        help='Output directory'
    )
    
    parser.add_argument(
        '--hackerone-token',
        type=str,
        help='HackerOne API token'
    )
    
    parser.add_argument(
        '--bugcrowd-token',
        type=str,
        help='Bugcrowd API token'
    )
    
    parser.add_argument(
        '--nvd-api-key',
        type=str,
        help='NVD API key'
    )
    
    parser.add_argument(
        '--days-back',
        type=int,
        default=365,
        help='For CVE collection: days to look back'
    )
    
    parser.add_argument(
        '--no-cache',
        action='store_true',
        help='Disable caching'
    )
    
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    use_cache = not args.no_cache
    
    print("="*70)
    print("BUGPREDICT AI - DATA COLLECTION")
    print("="*70)
    
    # HackerOne
    if args.source in ['hackerone', 'all']:
        print("\n[1] Collecting from HackerOne...")
        print("-"*70)
        
        collector = HackerOneCollector(
            api_token=args.hackerone_token
        )
        
        reports = collector.collect(
            limit=args.limit,
            use_cache=use_cache
        )
        
        print(f"✓ Collected {len(reports)} reports from HackerOne")
        
        # Save
        import pickle
        output_file = output_dir / 'hackerone_reports.pkl'
        with open(output_file, 'wb') as f:
            pickle.dump(reports, f)
        print(f"✓ Saved to {output_file}")
    
    # Bugcrowd
    if args.source in ['bugcrowd', 'all']:
        print("\n[2] Collecting from Bugcrowd...")
        print("-"*70)
        
        collector = BugcrowdCollector(
            api_token=args.bugcrowd_token
        )
        
        reports = collector.collect(
            limit=args.limit,
            use_cache=use_cache
        )
        
        print(f"✓ Collected {len(reports)} reports from Bugcrowd")
        
        # Save
        import pickle
        output_file = output_dir / 'bugcrowd_reports.pkl'
        with open(output_file, 'wb') as f:
            pickle.dump(reports, f)
        print(f"✓ Saved to {output_file}")
    
    # CVE/NVD
    if args.source in ['cve', 'all']:
        print("\n[3] Collecting from NVD...")
        print("-"*70)
        
        collector = CVECollector(
            api_key=args.nvd_api_key
        )
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=args.days_back)
        
        print(f"Date range: {start_date.date()} to {end_date.date()}")
        
        reports = collector.collect(
            start_date=start_date,
            end_date=end_date,
            keywords=['web', 'application'],
            limit=args.limit,
            use_cache=use_cache
        )
        
        print(f"✓ Collected {len(reports)} CVEs from NVD")
        
        # Save
        import pickle
        output_file = output_dir / 'cve_reports.pkl'
        with open(output_file, 'wb') as f:
            pickle.dump(reports, f)
        print(f"✓ Saved to {output_file}")
    
    print("\n" + "="*70)
    print("✓ DATA COLLECTION COMPLETE")
    print("="*70)


if __name__ == '__main__':
    main()
