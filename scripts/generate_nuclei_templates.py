#!/usr/bin/env python3
"""
Nuclei template generator
Generates Nuclei templates based on predictions
"""

import argparse
import json
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.inference.predictor import ThreatPredictor
from src.inference.template_generator import NucleiTemplateGenerator
from rich.console import Console


console = Console()


def main():
    parser = argparse.ArgumentParser(description='Generate Nuclei templates')
    
    parser.add_argument(
        '--target',
        '-t',
        required=True,
        help='Target domain'
    )
    
    parser.add_argument(
        '--output-dir',
        '-o',
        default='nuclei-templates/custom',
        help='Output directory for templates'
    )
    
    parser.add_argument(
        '--min-probability',
        type=float,
        default=0.5,
        help='Minimum probability threshold'
    )
    
    parser.add_argument(
        '--models-dir',
        default='data/models',
        help='Directory containing trained models'
    )
    
    args = parser.parse_args()
    
    # Load predictor
    console.print("[cyan]Loading models...[/cyan]")
    predictor = ThreatPredictor(models_dir=args.models_dir)
    
    # Analyze target
    console.print(f"[cyan]Analyzing {args.target}...[/cyan]")
    results = predictor.analyze_target({
        'domain': args.target,
        'company_name': '',
        'technology_stack': [],
        'endpoints': ['/'],
        'auth_required': False,
        'has_api': False
    })
    
    # Generate templates
    console.print(f"[cyan]Generating Nuclei templates...[/cyan]\n")
    
    generator = NucleiTemplateGenerator()
    generated = []
    
    for vuln in results['vulnerability_predictions']:
        if vuln['probability'] >= args.min_probability:
            template_path = generator.generate_template(
                vuln['vulnerability_type'],
                {'domain': args.target}
            )
            generated.append(template_path)
            console.print(f"  [green]✓[/green] Generated: {template_path}")
    
    console.print(f"\n[green]✓ Generated {len(generated)} templates[/green]")
    console.print(f"[green]✓ Saved to: {args.output_dir}[/green]")
    
    # Usage instructions
    console.print("\n[bold]Usage:[/bold]")
    console.print(f"  nuclei -t {args.output_dir} -u https://{args.target}")


if __name__ == '__main__':
    main()
