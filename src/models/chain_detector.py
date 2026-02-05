"""Vulnerability chain detection - Enhanced with comprehensive chain patterns"""

from typing import List, Dict, Set, Tuple, Optional
import networkx as nx
import numpy as np
from itertools import combinations
import json
from pathlib import Path


class ChainDetector:
    """
    Detects vulnerability chains and multi-step attack paths
    
    Enhanced Features:
    - 25+ pre-defined chain patterns
    - Graph-based chain discovery
    - Modern API/Cloud attack chains
    - GraphQL exploitation chains
    - Authentication bypass chains
    - Business logic exploitation chains
    """
    
    def __init__(self):
        self.chain_patterns = self._build_chain_patterns()
        self.vulnerability_graph = None
        self.discovered_chains = []
        self.chain_scores = {}
    
    def _build_chain_patterns(self) -> List[Dict]:
        """Define comprehensive vulnerability chain patterns"""
        
        patterns = [
            # ==================== ACCOUNT TAKEOVER CHAINS ====================
            {
                'name': 'Classic Account Takeover',
                'vulns': ['Information Disclosure', 'CSRF', 'Authentication Bypass'],
                'severity': 'critical',
                'description': 'Email enumeration → CSRF password reset → Auth bypass',
                'prerequisites': ['Information Disclosure'],
                'steps': [
                    'Enumerate valid user emails via error messages',
                    'Trigger CSRF to initiate password reset',
                    'Bypass authentication to complete reset'
                ],
                'impact': 'Full account compromise',
                'likelihood': 0.8,
                'attack_complexity': 'medium'
            },
            {
                'name': 'Session Hijacking Chain',
                'vulns': ['XSS', 'Information Disclosure', 'CSRF'],
                'severity': 'critical',
                'description': 'XSS → Session token theft → Session hijacking',
                'prerequisites': ['XSS'],
                'steps': [
                    'Execute XSS to steal session token',
                    'Disclosure of session management flaws',
                    'CSRF to perform actions as victim'
                ],
                'impact': 'Session takeover and unauthorized actions',
                'likelihood': 0.9,
                'attack_complexity': 'low'
            },
            {
                'name': 'JWT Account Takeover',
                'vulns': ['JWT Vulnerabilities', 'Broken Authentication', 'IDOR'],
                'severity': 'critical',
                'description': 'JWT none algorithm → Token manipulation → Account takeover',
                'prerequisites': ['JWT Vulnerabilities'],
                'steps': [
                    'Identify JWT with none algorithm accepted',
                    'Forge JWT token for other users',
                    'Access other accounts via IDOR with forged token'
                ],
                'impact': 'Mass account takeover',
                'likelihood': 0.75,
                'attack_complexity': 'medium'
            },
            
            # ==================== RCE CHAINS ====================
            {
                'name': 'File Upload to RCE',
                'vulns': ['File Upload', 'Path Traversal', 'Remote Code Execution'],
                'severity': 'critical',
                'description': 'Unrestricted file upload → Path traversal → Remote code execution',
                'prerequisites': ['File Upload'],
                'steps': [
                    'Upload malicious file (web shell)',
                    'Traverse to executable directory',
                    'Execute uploaded file to achieve RCE'
                ],
                'impact': 'Complete server compromise',
                'likelihood': 0.7,
                'attack_complexity': 'medium'
            },
            {
                'name': 'Deserialization to RCE',
                'vulns': ['Deserialization', 'Command Injection', 'Remote Code Execution'],
                'severity': 'critical',
                'description': 'Unsafe deserialization → Command injection → RCE',
                'prerequisites': ['Deserialization'],
                'steps': [
                    'Inject malicious serialized object',
                    'Trigger command injection during deserialization',
                    'Execute arbitrary commands'
                ],
                'impact': 'Complete server compromise',
                'likelihood': 0.6,
                'attack_complexity': 'high'
            },
            {
                'name': 'NoSQL Injection to RCE',
                'vulns': ['NoSQL Injection', 'Command Injection', 'Remote Code Execution'],
                'severity': 'critical',
                'description': 'NoSQL injection → Command injection → Server compromise',
                'prerequisites': ['NoSQL Injection'],
                'steps': [
                    'Exploit NoSQL injection (e.g., MongoDB $where)',
                    'Inject JavaScript code to execute commands',
                    'Achieve remote code execution'
                ],
                'impact': 'Complete server compromise',
                'likelihood': 0.65,
                'attack_complexity': 'medium'
            },
            
            # ==================== DATA EXFILTRATION CHAINS ====================
            {
                'name': 'IDOR to Data Breach',
                'vulns': ['IDOR', 'Information Disclosure', 'SSRF'],
                'severity': 'high',
                'description': 'IDOR → Information disclosure → SSRF for internal data',
                'prerequisites': ['IDOR'],
                'steps': [
                    'Exploit IDOR to access other users data',
                    'Discover internal endpoints via info disclosure',
                    'Use SSRF to exfiltrate internal data'
                ],
                'impact': 'Large-scale data breach',
                'likelihood': 0.7,
                'attack_complexity': 'medium'
            },
            {
                'name': 'SQL Injection to Full Database Dump',
                'vulns': ['SQL Injection', 'Information Disclosure', 'File Upload'],
                'severity': 'critical',
                'description': 'SQLi → Database enumeration → File write for persistence',
                'prerequisites': ['SQL Injection'],
                'steps': [
                    'Exploit SQL injection',
                    'Enumerate and dump database',
                    'Write web shell for persistent access'
                ],
                'impact': 'Complete database compromise',
                'likelihood': 0.8,
                'attack_complexity': 'low'
            },
            {
                'name': 'API Data Exfiltration Chain',
                'vulns': ['Excessive Data Exposure', 'IDOR', 'Rate Limiting Issues'],
                'severity': 'high',
                'description': 'API over-fetching → IDOR enumeration → Mass data extraction',
                'prerequisites': ['Excessive Data Exposure'],
                'steps': [
                    'Identify API endpoint with excessive data exposure',
                    'Enumerate user IDs via IDOR',
                    'Extract all data without rate limiting'
                ],
                'impact': 'Complete user database exfiltration',
                'likelihood': 0.75,
                'attack_complexity': 'low'
            },
            
            # ==================== PRIVILEGE ESCALATION CHAINS ====================
            {
                'name': 'IDOR to Admin Takeover',
                'vulns': ['IDOR', 'Business Logic', 'Broken Authorization'],
                'severity': 'critical',
                'description': 'IDOR → Logic flaw → Privilege escalation',
                'prerequisites': ['IDOR'],
                'steps': [
                    'Use IDOR to access admin user object',
                    'Exploit business logic flaw to modify privileges',
                    'Bypass authorization to admin panel'
                ],
                'impact': 'Administrative access',
                'likelihood': 0.75,
                'attack_complexity': 'medium'
            },
            {
                'name': 'Race Condition Privilege Escalation',
                'vulns': ['Race Condition', 'Business Logic', 'Broken Authorization'],
                'severity': 'high',
                'description': 'Race condition → Duplicate privileges → Admin access',
                'prerequisites': ['Race Condition'],
                'steps': [
                    'Identify race condition in privilege assignment',
                    'Send concurrent requests to duplicate admin role',
                    'Exploit broken authorization to maintain access'
                ],
                'impact': 'Unauthorized privilege escalation',
                'likelihood': 0.6,
                'attack_complexity': 'high'
            },
            
            # ==================== SSRF & CLOUD CHAINS ====================
            {
                'name': 'SSRF to Internal Network Compromise',
                'vulns': ['SSRF', 'Information Disclosure', 'Remote Code Execution'],
                'severity': 'critical',
                'description': 'SSRF → Internal service discovery → RCE on internal systems',
                'prerequisites': ['SSRF'],
                'steps': [
                    'Exploit SSRF to scan internal network',
                    'Discover vulnerable internal services',
                    'Exploit RCE on internal systems'
                ],
                'impact': 'Internal network compromise',
                'likelihood': 0.6,
                'attack_complexity': 'medium'
            },
            {
                'name': 'Cloud Metadata to Infrastructure Takeover',
                'vulns': ['SSRF', 'Cloud Misconfiguration', 'S3 Bucket Exposure'],
                'severity': 'critical',
                'description': 'SSRF → AWS metadata → Credential theft → S3 access',
                'prerequisites': ['SSRF'],
                'steps': [
                    'Exploit SSRF to access 169.254.169.254',
                    'Extract IAM credentials from metadata endpoint',
                    'Use credentials to access S3 buckets',
                    'Exfiltrate data or modify infrastructure'
                ],
                'impact': 'Complete cloud infrastructure compromise',
                'likelihood': 0.85,
                'attack_complexity': 'low'
            },
            
            # ==================== GRAPHQL CHAINS ====================
            {
                'name': 'GraphQL Introspection to Data Breach',
                'vulns': ['GraphQL Introspection', 'Excessive Data Exposure', 'IDOR'],
                'severity': 'critical',
                'description': 'GraphQL schema leak → Over-fetching → Data exfiltration',
                'prerequisites': ['GraphQL Introspection'],
                'steps': [
                    'Enumerate GraphQL schema via introspection',
                    'Craft queries to over-fetch sensitive data',
                    'Exploit IDOR to access other users data',
                    'Extract complete database'
                ],
                'impact': 'Complete database exposure',
                'likelihood': 0.8,
                'attack_complexity': 'low'
            },
            {
                'name': 'GraphQL Batching DoS to Exploitation',
                'vulns': ['GraphQL Batching Abuse', 'Rate Limiting Issues', 'Business Logic'],
                'severity': 'high',
                'description': 'Batch query abuse → Resource exhaustion → Logic bypass',
                'prerequisites': ['GraphQL Batching Abuse'],
                'steps': [
                    'Send deeply nested batched queries',
                    'Exhaust server resources (DoS)',
                    'Exploit business logic during degraded state'
                ],
                'impact': 'Service disruption and logic bypass',
                'likelihood': 0.65,
                'attack_complexity': 'medium'
            },
            
            # ==================== API SECURITY CHAINS ====================
            {
                'name': 'API Rate Limit Bypass to Account Takeover',
                'vulns': ['Rate Limiting Issues', 'Broken Authentication', 'IDOR'],
                'severity': 'high',
                'description': 'No rate limiting → Brute force → Account access',
                'prerequisites': ['Rate Limiting Issues'],
                'steps': [
                    'Identify endpoint with no rate limiting',
                    'Brute force credentials or OTP codes',
                    'Exploit IDOR to access other accounts'
                ],
                'impact': 'Mass account compromise',
                'likelihood': 0.7,
                'attack_complexity': 'low'
            },
            {
                'name': 'API Abuse to Business Logic Bypass',
                'vulns': ['API Abuse', 'Business Logic', 'Excessive Data Exposure'],
                'severity': 'high',
                'description': 'API enumeration → Logic flaw discovery → Exploitation',
                'prerequisites': ['API Abuse'],
                'steps': [
                    'Enumerate hidden API endpoints',
                    'Discover business logic flaws',
                    'Exploit excessive data exposure for sensitive info'
                ],
                'impact': 'Business logic bypass and data leak',
                'likelihood': 0.65,
                'attack_complexity': 'medium'
            },
            
            # ==================== XSS CHAINS ====================
            {
                'name': 'Stored XSS to Account Takeover',
                'vulns': ['XSS', 'CSRF', 'Authentication Bypass'],
                'severity': 'high',
                'description': 'Stored XSS → Session theft → Account takeover',
                'prerequisites': ['XSS'],
                'steps': [
                    'Inject stored XSS payload in user-generated content',
                    'Victim triggers XSS, session token stolen',
                    'Use stolen session to takeover account'
                ],
                'impact': 'Account compromise at scale',
                'likelihood': 0.8,
                'attack_complexity': 'low'
            },
            {
                'name': 'DOM XSS to Sensitive Data Theft',
                'vulns': ['XSS', 'Information Disclosure', 'Token/Credential Leakage'],
                'severity': 'high',
                'description': 'DOM XSS → Extract tokens → API access',
                'prerequisites': ['XSS'],
                'steps': [
                    'Exploit DOM-based XSS',
                    'Extract API tokens from localStorage/sessionStorage',
                    'Use tokens to access API endpoints'
                ],
                'impact': 'API credential theft and data access',
                'likelihood': 0.75,
                'attack_complexity': 'medium'
            },
            
            # ==================== BUSINESS LOGIC CHAINS ====================
            {
                'name': 'Payment Bypass Chain',
                'vulns': ['Business Logic', 'IDOR', 'CSRF'],
                'severity': 'high',
                'description': 'Price manipulation → Order ID manipulation → Payment bypass',
                'prerequisites': ['Business Logic'],
                'steps': [
                    'Manipulate product price in request',
                    'Use IDOR to access other users payment methods',
                    'CSRF to complete unauthorized transaction'
                ],
                'impact': 'Financial fraud',
                'likelihood': 0.7,
                'attack_complexity': 'medium'
            },
            {
                'name': 'Race Condition Financial Exploit',
                'vulns': ['Race Condition', 'Business Logic', 'Rate Limiting Issues'],
                'severity': 'critical',
                'description': 'Race condition → Double spending → Financial loss',
                'prerequisites': ['Race Condition'],
                'steps': [
                    'Identify race condition in payment processing',
                    'Send concurrent payment requests',
                    'Exploit business logic to duplicate credits/funds'
                ],
                'impact': 'Financial fraud via double spending',
                'likelihood': 0.55,
                'attack_complexity': 'high'
            },
            
            # ==================== AUTHENTICATION CHAINS ====================
            {
                'name': 'Password Reset Poisoning',
                'vulns': ['Host Header Injection', 'Information Disclosure', 'Account Takeover'],
                'severity': 'critical',
                'description': 'Host header injection → Password reset link manipulation',
                'prerequisites': ['Host Header Injection'],
                'steps': [
                    'Inject malicious host header in password reset request',
                    'Victim receives reset link with attacker domain',
                    'Steal reset token and takeover account'
                ],
                'impact': 'Account takeover via reset poisoning',
                'likelihood': 0.7,
                'attack_complexity': 'medium'
            },
            {
                'name': 'Session Fixation to Account Takeover',
                'vulns': ['Session Fixation', 'CSRF', 'Broken Authentication'],
                'severity': 'high',
                'description': 'Session fixation → Force victim session → Account access',
                'prerequisites': ['Session Fixation'],
                'steps': [
                    'Fix victim session ID before authentication',
                    'Victim logs in with fixed session',
                    'Attacker uses same session to access account'
                ],
                'impact': 'Account takeover',
                'likelihood': 0.65,
                'attack_complexity': 'medium'
            },
            
            # ==================== CONFIGURATION CHAINS ====================
            {
                'name': 'CORS to Credential Theft',
                'vulns': ['CORS Misconfiguration', 'Information Disclosure', 'Token/Credential Leakage'],
                'severity': 'high',
                'description': 'CORS wildcard → Cross-origin data theft → Token leakage',
                'prerequisites': ['CORS Misconfiguration'],
                'steps': [
                    'Identify CORS misconfiguration (null origin or wildcard)',
                    'Make cross-origin requests to steal data',
                    'Extract authentication tokens or credentials'
                ],
                'impact': 'Cross-origin data theft and credential leakage',
                'likelihood': 0.75,
                'attack_complexity': 'low'
            },
            {
                'name': 'Exposed Admin to Full Compromise',
                'vulns': ['Exposed Admin Interface', 'Broken Authentication', 'Privilege Escalation'],
                'severity': 'critical',
                'description': 'Exposed admin panel → Weak auth → Full system access',
                'prerequisites': ['Exposed Admin Interface'],
                'steps': [
                    'Discover exposed administrative interface',
                    'Exploit weak authentication (default creds, brute force)',
                    'Escalate privileges to full system access'
                ],
                'impact': 'Complete administrative takeover',
                'likelihood': 0.8,
                'attack_complexity': 'low'
            },
            
            # ==================== WEBHOOK & CALLBACK CHAINS ====================
            {
                'name': 'Webhook SSRF to Internal Access',
                'vulns': ['Webhook Abuse', 'SSRF', 'Cloud Misconfiguration'],
                'severity': 'high',
                'description': 'Webhook SSRF → Internal network scanning → Cloud metadata',
                'prerequisites': ['Webhook Abuse'],
                'steps': [
                    'Register webhook with internal URL',
                    'Trigger SSRF via webhook callback',
                    'Access cloud metadata or internal services'
                ],
                'impact': 'Internal network and cloud compromise',
                'likelihood': 0.7,
                'attack_complexity': 'medium'
            },
            
            # ==================== CACHE POISONING CHAINS ====================
            {
                'name': 'Cache Poisoning to XSS',
                'vulns': ['Cache Poisoning', 'XSS', 'Information Disclosure'],
                'severity': 'high',
                'description': 'Cache poisoning → Stored XSS → Mass exploitation',
                'prerequisites': ['Cache Poisoning'],
                'steps': [
                    'Poison web cache with XSS payload',
                    'Cached malicious response served to all users',
                    'Mass XSS exploitation of all victims'
                ],
                'impact': 'Widespread XSS affecting all users',
                'likelihood': 0.6,
                'attack_complexity': 'high'
            },
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
            
            # Also detect partial chains (useful for recommendations)
            elif len(required_vulns.intersection(vuln_set)) >= 2:
                missing = required_vulns - vuln_set
                chain_info = pattern.copy()
                chain_info['exploitability_score'] = self.calculate_chain_score(pattern, vulnerabilities) * 0.5
                chain_info['present_vulnerabilities'] = list(required_vulns.intersection(vuln_set))
                chain_info['missing_prerequisites'] = list(missing)
                chain_info['partial'] = True
                
                # Only include partial chains if they're high severity
                if pattern['severity'] in ['critical', 'high']:
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
        - Base severity (40%)
        - Chain likelihood (30%)
        - Attack complexity (20%)
        - Vulnerability prevalence (10%)
        
        Returns:
            Score from 0-10
        """
        
        # Base severity score (40% weight)
        severity_scores = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5
        }
        base_score = severity_scores.get(chain['severity'], 5.0) * 0.4
        
        # Likelihood multiplier (30% weight)
        likelihood = chain.get('likelihood', 0.5) * 10 * 0.3
        
        # Complexity factor (20% weight) - inverse relationship
        complexity_scores = {
            'low': 10.0,
            'medium': 6.0,
            'high': 3.0
        }
        complexity = chain.get('attack_complexity', 'medium')
        complexity_score = complexity_scores.get(complexity, 6.0) * 0.2
        
        # Vulnerability prevalence (10% weight)
        # More steps = potentially harder to exploit
        chain_length = len(chain['vulns'])
        prevalence_score = (1.0 / (1.0 + (chain_length - 2) * 0.3)) * 10 * 0.1
        
        # Combined score
        total_score = base_score + likelihood + complexity_score + prevalence_score
        
        return round(total_score, 2)
    
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
        
        # Define "can lead to" relationships
        transitions = {
            # From Access Control issues
            'IDOR': ['Information Disclosure', 'Business Logic', 'Broken Authorization', 'Excessive Data Exposure'],
            'Broken Authorization': ['Privilege Escalation', 'IDOR', 'Account Takeover'],
            
            # From Authentication issues
            'Broken Authentication': ['Account Takeover', 'Session Fixation', 'Privilege Escalation'],
            'JWT Vulnerabilities': ['Broken Authentication', 'Account Takeover', 'IDOR'],
            'Session Fixation': ['Account Takeover', 'CSRF'],
            
            # From Injection attacks
            'XSS': ['CSRF', 'Information Disclosure', 'Token/Credential Leakage', 'Account Takeover'],
            'SQL Injection': ['Information Disclosure', 'Remote Code Execution', 'File Upload'],
            'NoSQL Injection': ['Information Disclosure', 'Remote Code Execution', 'Command Injection'],
            'Command Injection': ['Remote Code Execution'],
            
            # From SSRF
            'SSRF': ['Information Disclosure', 'Remote Code Execution', 'Cloud Misconfiguration'],
            'Cloud Misconfiguration': ['S3 Bucket Exposure', 'Information Disclosure', 'Remote Code Execution'],
            
            # From API issues
            'API Abuse': ['Business Logic', 'Excessive Data Exposure', 'IDOR'],
            'GraphQL Introspection': ['Excessive Data Exposure', 'IDOR', 'Business Logic'],
            'GraphQL Batching Abuse': ['Business Logic', 'Rate Limiting Issues'],
            'Excessive Data Exposure': ['Information Disclosure', 'Token/Credential Leakage'],
            'Rate Limiting Issues': ['Broken Authentication', 'Business Logic', 'Account Takeover'],
            
            # From Business Logic
            'Business Logic': ['IDOR', 'Broken Authorization', 'Privilege Escalation'],
            'Race Condition': ['Business Logic', 'Privilege Escalation'],
            
            # From File operations
            'File Upload': ['Path Traversal', 'Remote Code Execution'],
            'Path Traversal': ['Remote Code Execution', 'Information Disclosure'],
            
            # From Deserialization
            'Deserialization': ['Remote Code Execution', 'Command Injection'],
            
            # From Web attacks
            'CSRF': ['Account Takeover', 'Business Logic', 'Broken Authorization'],
            'Host Header Injection': ['Account Takeover', 'Cache Poisoning'],
            'Cache Poisoning': ['XSS', 'Information Disclosure'],
            
            # From Configuration
            'CORS Misconfiguration': ['Information Disclosure', 'Token/Credential Leakage'],
            'Exposed Admin Interface': ['Broken Authentication', 'Privilege Escalation'],
            
            # From Webhooks
            'Webhook Abuse': ['SSRF', 'Information Disclosure'],
        }
        
        # Add edges
        for source, targets in transitions.items():
            if source in vulnerabilities:
                for target in targets:
                    if target in vulnerabilities:
                        # Weight based on likelihood of transition
                        G.add_edge(source, target, weight=1.0)
        
        self.vulnerability_graph = G
        
        return G
    
    def find_attack_paths(self, vulnerabilities: List[str], 
                          max_length: int = 5) -> List[List[str]]:
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
        
        # Sort by path length and score
        unique_paths.sort(key=lambda p: (len(p), -self._score_path(p)), reverse=True)
        
        return unique_paths
    
    def _score_path(self, path: List[str]) -> float:
        """Score an attack path based on vulnerabilities involved"""
        
        high_impact_vulns = {
            'Remote Code Execution': 10,
            'Account Takeover': 9,
            'Privilege Escalation': 9,
            'SQL Injection': 8,
            'Cloud Misconfiguration': 8,
        }
        
        score = sum(high_impact_vulns.get(vuln, 5) for vuln in path)
        return score / len(path)  # Average score
    
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
            key=lambda c: (c['exploitability_score'], -len(c.get('missing_prerequisites', []))),
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
        
        is_partial = chain.get('partial', False)
        
        scenario = f"""
{'[PARTIAL CHAIN] ' if is_partial else ''}ATTACK CHAIN: {chain['name']}
{'='*70}

Severity: {chain['severity'].upper()}
Exploitability Score: {chain['exploitability_score']}/10
Likelihood: {chain.get('likelihood', 0) * 100:.0f}%
Attack Complexity: {chain.get('attack_complexity', 'medium').upper()}

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
✓ Present: {', '.join(chain['present_vulnerabilities'])}
"""
        
        if chain.get('missing_prerequisites'):
            scenario += f"✗ Missing: {', '.join(chain['missing_prerequisites'])}\n"
        
        return scenario
    
    def get_chain_statistics(self) -> Dict:
        """Get statistics about detected chains"""
        
        if not self.discovered_chains:
            return {
                'total_chains': 0,
                'complete_chains': 0,
                'partial_chains': 0,
                'critical_chains': 0,
                'high_chains': 0,
                'avg_score': 0.0,
                'max_score': 0.0
            }
        
        complete_chains = [c for c in self.discovered_chains if not c.get('partial', False)]
        partial_chains = [c for c in self.discovered_chains if c.get('partial', False)]
        
        stats = {
            'total_chains': len(self.discovered_chains),
            'complete_chains': len(complete_chains),
            'partial_chains': len(partial_chains),
            'critical_chains': sum(1 for c in self.discovered_chains if c['severity'] == 'critical'),
            'high_chains': sum(1 for c in self.discovered_chains if c['severity'] == 'high'),
            'medium_chains': sum(1 for c in self.discovered_chains if c['severity'] == 'medium'),
            'avg_score': np.mean([c['exploitability_score'] for c in self.discovered_chains]),
            'max_score': max(c['exploitability_score'] for c in self.discovered_chains),
            'unique_vulns_in_chains': len(set(
                vuln for chain in self.discovered_chains 
                for vuln in chain['present_vulnerabilities']
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
