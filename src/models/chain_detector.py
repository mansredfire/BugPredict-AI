"""Vulnerability chain detection - Production Implementation"""

from typing import List, Dict, Set, Tuple, Optional
import networkx as nx
import numpy as np
from itertools import combinations
import json
from pathlib import Path


class ChainDetector:
    """
    Detects vulnerability chains and multi-step attack paths
    
    Features:
    - Pre-defined chain patterns (common attack chains)
    - Graph-based chain discovery (finds novel chains)
    - Chain scoring and ranking
    - Attack path generation
    """
    
    def __init__(self):
        self.chain_patterns = self._build_chain_patterns()
        self.vulnerability_graph = None
        self.discovered_chains = []
        self.chain_scores = {}
    
    def _build_chain_patterns(self) -> List[Dict]:
        """Define known vulnerability chain patterns"""
        
        patterns = [
            # Account Takeover Chains
            {
                'name': 'Classic Account Takeover',
                'vulns': ['INFO_DISCLOSURE', 'CSRF', 'AUTH_BYPASS'],
                'severity': 'critical',
                'description': 'Email enumeration → CSRF password reset → Auth bypass',
                'prerequisites': ['INFO_DISCLOSURE'],
                'steps': [
                    'Enumerate valid user emails via error messages',
                    'Trigger CSRF to initiate password reset',
                    'Bypass authentication to complete reset'
                ],
                'impact': 'Full account compromise',
                'likelihood': 0.8
            },
            {
                'name': 'Session Hijacking Chain',
                'vulns': ['XSS', 'INFO_DISCLOSURE', 'CSRF'],
                'severity': 'critical',
                'description': 'XSS → Session token theft → Session hijacking',
                'prerequisites': ['XSS'],
                'steps': [
                    'Execute XSS to steal session token',
                    'Disclosure of session management flaws',
                    'CSRF to perform actions as victim'
                ],
                'impact': 'Session takeover and unauthorized actions',
                'likelihood': 0.9
            },
            
            # RCE Chains
            {
                'name': 'File Upload to RCE',
                'vulns': ['FILE_UPLOAD', 'PATH_TRAVERSAL', 'RCE'],
                'severity': 'critical',
                'description': 'Unrestricted file upload → Path traversal → Remote code execution',
                'prerequisites': ['FILE_UPLOAD'],
                'steps': [
                    'Upload malicious file',
                    'Traverse to executable directory',
                    'Execute uploaded file'
                ],
                'impact': 'Complete server compromise',
                'likelihood': 0.7
            },
            {
                'name': 'Deserialization to RCE',
                'vulns': ['DESERIALIZATION', 'COMMAND_INJECTION', 'RCE'],
                'severity': 'critical',
                'description': 'Unsafe deserialization → Command injection → RCE',
                'prerequisites': ['DESERIALIZATION'],
                'steps': [
                    'Inject malicious serialized object',
                    'Trigger command injection during deserialization',
                    'Execute arbitrary commands'
                ],
                'impact': 'Complete server compromise',
                'likelihood': 0.6
            },
            
            # Data Exfiltration Chains
            {
                'name': 'IDOR to Data Breach',
                'vulns': ['IDOR', 'INFO_DISCLOSURE', 'SSRF'],
                'severity': 'high',
                'description': 'IDOR → Information disclosure → SSRF for internal data',
                'prerequisites': ['IDOR'],
                'steps': [
                    'Exploit IDOR to access other users data',
                    'Discover internal endpoints',
                    'Use SSRF to exfiltrate internal data'
                ],
                'impact': 'Large-scale data breach',
                'likelihood': 0.7
            },
            {
                'name': 'SQL Injection to Full Database Dump',
                'vulns': ['SQL Injection', 'INFO_DISCLOSURE', 'FILE_UPLOAD'],
                'severity': 'critical',
                'description': 'SQLi → Database enumeration → File write for persistence',
                'prerequisites': ['SQL Injection'],
                'steps': [
                    'Exploit SQL injection',
                    'Enumerate and dump database',
                    'Write web shell for persistent access'
                ],
                'impact': 'Complete database compromise',
                'likelihood': 0.8
            },
            
            # Privilege Escalation Chains
            {
                'name': 'IDOR to Admin Takeover',
                'vulns': ['IDOR', 'BUSINESS_LOGIC', 'AUTH_BYPASS'],
                'severity': 'critical',
                'description': 'IDOR → Logic flaw → Privilege escalation',
                'prerequisites': ['IDOR'],
                'steps': [
                    'Use IDOR to access admin user object',
                    'Exploit business logic flaw to modify privileges',
                    'Bypass authentication to admin panel'
                ],
                'impact': 'Administrative access',
                'likelihood': 0.75
            },
            {
                'name': 'Race Condition Privilege Escalation',
                'vulns': ['BUSINESS_LOGIC', 'CSRF', 'AUTH_BYPASS'],
                'severity': 'high',
                'description': 'Race condition → Duplicate privileges → Admin access',
                'prerequisites': ['BUSINESS_LOGIC'],
                'steps': [
                    'Identify race condition in privilege assignment',
                    'Send concurrent requests to duplicate admin role',
                    'Bypass checks to maintain elevated privileges'
                ],
                'impact': 'Unauthorized privilege escalation',
                'likelihood': 0.5
            },
            
            # SSRF Chains
            {
                'name': 'SSRF to Internal Network Compromise',
                'vulns': ['SSRF', 'INFO_DISCLOSURE', 'RCE'],
                'severity': 'critical',
                'description': 'SSRF → Internal service discovery → RCE on internal systems',
                'prerequisites': ['SSRF'],
                'steps': [
                    'Exploit SSRF to scan internal network',
                    'Discover vulnerable internal services',
                    'Exploit RCE on internal systems'
                ],
                'impact': 'Internal network compromise',
                'likelihood': 0.6
            },
            {
                'name': 'SSRF to Cloud Metadata Exploitation',
                'vulns': ['SSRF', 'INFO_DISCLOSURE'],
                'severity': 'critical',
                'description': 'SSRF → Cloud metadata access → Credential theft',
                'prerequisites': ['SSRF'],
                'steps': [
                    'Use SSRF to access cloud metadata endpoint (169.254.169.254)',
                    'Extract IAM credentials',
                    'Use credentials to access cloud resources'
                ],
                'impact': 'Cloud infrastructure compromise',
                'likelihood': 0.85
            },
            
            # XSS Chains
            {
                'name': 'Stored XSS to Account Takeover',
                'vulns': ['XSS', 'CSRF', 'AUTH_BYPASS'],
                'severity': 'high',
                'description': 'Stored XSS → Session theft → Account takeover',
                'prerequisites': ['XSS'],
                'steps': [
                    'Inject stored XSS payload',
                    'Victim triggers XSS, session token stolen',
                    'Use stolen session to takeover account'
                ],
                'impact': 'Account compromise at scale',
                'likelihood': 0.8
            },
            
            # Business Logic Chains
            {
                'name': 'Payment Bypass Chain',
                'vulns': ['BUSINESS_LOGIC', 'IDOR', 'CSRF'],
                'severity': 'high',
                'description': 'Price manipulation → Order ID manipulation → Payment bypass',
                'prerequisites': ['BUSINESS_LOGIC'],
                'steps': [
                    'Manipulate product price in request',
                    'Use IDOR to access other users payment methods',
                    'CSRF to complete unauthorized transaction'
                ],
                'impact': 'Financial fraud',
                'likelihood': 0.7
            }
        ]
        
        return patterns
    
    def detect_chains(self, vulnerabilities: List[str]) -> List[Dict]:
        """
        Detect if vulnerabilities form known attack chains
        
        Args:
            vulnerabilities: List of vulnerability types found
            
        Returns:
            List of detected chains with metadata
        """
        
        detected_chains = []
        vuln_set = set(vulnerabilities)
        
        for pattern in self.chain_patterns:
            required_vulns = set(pattern['vulns'])
            
            # Check if all required vulnerabilities are present
            if required_vulns.issubset(vuln_set):
                # Calculate chain score
                score = self.calculate_chain_score(pattern, vulnerabilities)
                
                chain_info = pattern.copy()
                chain_info['exploitability_score'] = score
                chain_info['present_vulnerabilities'] = list(required_vulns)
                chain_info['missing_prerequisites'] = []
                
                detected_chains.append(chain_info)
        
        # Sort by exploitability score
        detected_chains.sort(key=lambda x: x['exploitability_score'], reverse=True)
        
        self.discovered_chains = detected_chains
        
        return detected_chains
    
    def calculate_chain_score(self, chain: Dict, 
                              vulnerabilities: List[str]) -> float:
        """
        Calculate exploitability score for a chain
        
        Factors:
        - Base severity
        - Chain likelihood
        - Complexity (inverse of chain length)
        - Vulnerability prevalence
        
        Returns:
            Score from 0-10
        """
        
        # Base severity score
        severity_scores = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5
        }
        base_score = severity_scores.get(chain['severity'], 5.0)
        
        # Likelihood multiplier
        likelihood = chain.get('likelihood', 0.5)
        
        # Complexity factor (inverse of chain length)
        chain_length = len(chain['vulns'])
        complexity_factor = 1.0 / (1.0 + (chain_length - 1) * 0.2)
        
        # Combined score
        score = base_score * likelihood * complexity_factor
        
        return round(score, 2)
    
    def build_vulnerability_graph(self, vulnerabilities: List[str]) -> nx.DiGraph:
        """
        Build directed graph of vulnerability relationships
        
        Args:
            vulnerabilities: List of vulnerability types
            
        Returns:
            NetworkX directed graph
        """
        
        G = nx.DiGraph()
        
        # Add nodes for each vulnerability
        for vuln in vulnerabilities:
            G.add_node(vuln)
        
        # Add edges based on common attack patterns
        # These represent "can lead to" relationships
        transitions = {
            'INFO_DISCLOSURE': ['CSRF', 'IDOR', 'AUTH_BYPASS'],
            'XSS': ['CSRF', 'INFO_DISCLOSURE', 'SESSION_HIJACKING'],
            'CSRF': ['AUTH_BYPASS', 'BUSINESS_LOGIC'],
            'IDOR': ['INFO_DISCLOSURE', 'BUSINESS_LOGIC', 'AUTH_BYPASS'],
            'SQL Injection': ['INFO_DISCLOSURE', 'RCE', 'FILE_UPLOAD'],
            'SSRF': ['INFO_DISCLOSURE', 'RCE', 'CLOUD_COMPROMISE'],
            'FILE_UPLOAD': ['PATH_TRAVERSAL', 'RCE'],
            'PATH_TRAVERSAL': ['RCE', 'INFO_DISCLOSURE'],
            'DESERIALIZATION': ['RCE', 'COMMAND_INJECTION'],
            'BUSINESS_LOGIC': ['IDOR', 'AUTH_BYPASS', 'PRIVILEGE_ESCALATION']
        }
        
        # Add edges
        for source, targets in transitions.items():
            if source in vulnerabilities:
                for target in targets:
                    if target in vulnerabilities:
                        G.add_edge(source, target, weight=1.0)
        
        self.vulnerability_graph = G
        
        return G
    
    def find_attack_paths(self, vulnerabilities: List[str], 
                          max_length: int = 4) -> List[List[str]]:
        """
        Find all possible attack paths in vulnerability graph
        
        Args:
            vulnerabilities: List of vulnerability types
            max_length: Maximum path length
            
        Returns:
            List of attack paths (each path is a list of vulnerabilities)
        """
        
        if self.vulnerability_graph is None:
            self.build_vulnerability_graph(vulnerabilities)
        
        paths = []
        
        # Find all simple paths between all pairs of nodes
        for source in self.vulnerability_graph.nodes():
            for target in self.vulnerability_graph.nodes():
                if source != target:
                    try:
                        all_paths = nx.all_simple_paths(
                            self.vulnerability_graph,
                            source,
                            target,
                            cutoff=max_length
                        )
                        
                        for path in all_paths:
                            if len(path) >= 2:  # At least 2 vulnerabilities
                                paths.append(path)
                    except nx.NetworkXNoPath:
                        continue
        
        # Remove duplicate paths
        unique_paths = []
        seen = set()
        
        for path in paths:
            path_tuple = tuple(path)
            if path_tuple not in seen:
                seen.add(path_tuple)
                unique_paths.append(path)
        
        return unique_paths
    
    def rank_chains(self, chains: Optional[List[Dict]] = None) -> List[Dict]:
        """
        Rank detected chains by exploitability
        
        Args:
            chains: Optional list of chains to rank (uses self.discovered_chains if None)
            
        Returns:
            Ranked list of chains
        """
        
        if chains is None:
            chains = self.discovered_chains
        
        if not chains:
            return []
        
        # Sort by exploitability score
        ranked = sorted(
            chains,
            key=lambda c: c['exploitability_score'],
            reverse=True
        )
        
        # Add rank
        for i, chain in enumerate(ranked, 1):
            chain['rank'] = i
        
        return ranked
    
    def generate_attack_scenario(self, chain: Dict) -> str:
        """
        Generate human-readable attack scenario from chain
        
        Args:
            chain: Chain dictionary
            
        Returns:
            Formatted attack scenario description
        """
        
        scenario = f"""
ATTACK CHAIN: {chain['name']}
{'='*70}

Severity: {chain['severity'].upper()}
Exploitability Score: {chain['exploitability_score']}/10
Likelihood: {chain.get('likelihood', 0) * 100:.0f}%

Description:
{chain['description']}

Attack Steps:
"""
        
        for i, step in enumerate(chain['steps'], 1):
            scenario += f"{i}. {step}\n"
        
        scenario += f"""
Impact:
{chain['impact']}

Required Vulnerabilities:
{', '.join(chain['vulns'])}
"""
        
        return scenario
    
    def get_chain_statistics(self) -> Dict:
        """Get statistics about detected chains"""
        
        if not self.discovered_chains:
            return {
                'total_chains': 0,
                'critical_chains': 0,
                'high_chains': 0,
                'avg_score': 0.0
            }
        
        stats = {
            'total_chains': len(self.discovered_chains),
            'critical_chains': sum(1 for c in self.discovered_chains if c['severity'] == 'critical'),
            'high_chains': sum(1 for c in self.discovered_chains if c['severity'] == 'high'),
            'medium_chains': sum(1 for c in self.discovered_chains if c['severity'] == 'medium'),
            'avg_score': np.mean([c['exploitability_score'] for c in self.discovered_chains]),
            'max_score': max(c['exploitability_score'] for c in self.discovered_chains),
            'unique_vulns_in_chains': len(set(
                vuln for chain in self.discovered_chains for vuln in chain['vulns']
            ))
        }
        
        return stats
    
    def save(self, filepath: str):
        """Save chain detector state"""
        
        save_path = Path(filepath)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        state = {
            'chain_patterns': self.chain_patterns,
            'discovered_chains': self.discovered_chains,
            'chain_scores': self.chain_scores
        }
        
        with open(filepath, 'w') as f:
            json.dump(state, f, indent=2)
        
        print(f"Saved ChainDetector to {filepath}")
    
    @classmethod
    def load(cls, filepath: str):
        """Load chain detector state"""
        
        with open(filepath, 'r') as f:
            state = json.load(f)
        
        detector = cls()
        detector.chain_patterns = state['chain_patterns']
        detector.discovered_chains = state['discovered_chains']
        detector.chain_scores = state['chain_scores']
        
        print(f"Loaded ChainDetector from {filepath}")
        
        return detector
