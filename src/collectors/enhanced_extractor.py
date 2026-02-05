"""Enhanced vulnerability type extraction"""

from typing import List, Dict
import re


class EnhancedVulnerabilityExtractor:
    """
    Enhanced vulnerability type detection
    Includes modern API, cloud, and advanced vulnerability types
    """
    
    def __init__(self):
        self.type_keywords = self._build_keyword_mapping()
    
    def _build_keyword_mapping(self) -> Dict[str, List[str]]:
        """Build comprehensive keyword mapping"""
        
        return {
            # Access Control
            'IDOR': [
                'idor', 'insecure direct object', 'broken access control',
                'unauthorized access', 'object reference', 'resource manipulation'
            ],
            'Broken Authorization': [
                'authorization bypass', 'broken authorization', 'missing authorization',
                'vertical privilege', 'horizontal privilege', 'function level'
            ],
            'Privilege Escalation': [
                'privilege escalation', 'privesc', 'escalate privileges',
                'elevate privileges', 'gain admin', 'become admin'
            ],
            
            # Authentication
            'Authentication Bypass': [
                'auth bypass', 'authentication bypass', 'login bypass',
                'broken authentication', 'authentication flaw'
            ],
            'Session Fixation': [
                'session fixation', 'session hijacking', 'session token',
                'session id predictable'
            ],
            'JWT Vulnerabilities': [
                'jwt', 'json web token', 'jwt none algorithm', 'jwt signature',
                'jwt weak secret', 'jwt manipulation'
            ],
            'Broken Authentication': [
                'weak password', 'default credentials', 'credential stuffing',
                'password spray', 'brute force', 'weak authentication'
            ],
            
            # Injection
            'SQL Injection': [
                'sql injection', 'sqli', 'sql', 'union select', 'blind sql',
                'time-based sql', 'error-based sql', 'boolean sql'
            ],
            'NoSQL Injection': [
                'nosql injection', 'nosql', 'mongodb injection', 'mongo injection',
                'cassandra injection', 'couchdb injection', 'operator injection'
            ],
            'Command Injection': [
                'command injection', 'os command', 'shell injection',
                'code injection', 'rce via command'
            ],
            'GraphQL Injection': [
                'graphql injection', 'graphql mutation', 'graphql query injection',
                'graphql sql injection'
            ],
            'Host Header Injection': [
                'host header injection', 'host header poisoning',
                'host header manipulation', 'cache poisoning via host'
            ],
            'HTTP Parameter Pollution': [
                'hpp', 'http parameter pollution', 'parameter pollution',
                'parameter tampering'
            ],
            
            # XSS variants
            'XSS': [
                'xss', 'cross-site scripting', 'cross site scripting',
                'reflected xss', 'stored xss', 'dom xss', 'dom-based xss',
                'self xss', 'blind xss', 'universal xss'
            ],
            
            # SSRF and related
            'SSRF': [
                'ssrf', 'server-side request forgery', 'server side request',
                'internal port scan', 'internal network access'
            ],
            'Cloud Misconfiguration': [
                'cloud misconfiguration', 'aws misconfiguration',
                'azure misconfiguration', 'gcp misconfiguration',
                'metadata endpoint', '169.254.169.254', 'cloud metadata'
            ],
            'S3 Bucket Exposure': [
                's3 bucket', 'exposed s3', 'public bucket', 's3 misconfiguration',
                'aws s3 leak', 'bucket enumeration'
            ],
            
            # API Security
            'API Abuse': [
                'api abuse', 'api misuse', 'api endpoint abuse',
                'rest api abuse', 'api vulnerability'
            ],
            'Excessive Data Exposure': [
                'excessive data', 'mass assignment', 'over-fetching',
                'api data leak', 'unnecessary data exposure', 'verbose response'
            ],
            'Rate Limiting Issues': [
                'rate limit', 'rate limiting', 'brute force possible',
                'no rate limit', 'missing rate limit', 'unlimited requests',
                'dos via', 'resource exhaustion'
            ],
            'GraphQL Introspection': [
                'graphql introspection', 'exposed schema', 'graphql schema leak',
                'introspection enabled', '__schema'
            ],
            'GraphQL Batching Abuse': [
                'graphql batching', 'batch attack', 'graphql query batching',
                'batched queries', 'nested queries'
            ],
            
            # Business Logic
            'Business Logic': [
                'business logic', 'logic flaw', 'workflow bypass',
                'payment bypass', 'discount abuse', 'price manipulation',
                'quantity manipulation', 'coupon abuse'
            ],
            'Race Condition': [
                'race condition', 'race condition attack', 'toctou',
                'time of check', 'concurrent request', 'parallel request',
                'double spending', 'parallel processing'
            ],
            'Webhook Abuse': [
                'webhook', 'webhook abuse', 'webhook injection',
                'webhook bypass', 'callback manipulation'
            ],
            
            # Data Exposure
            'Information Disclosure': [
                'information disclosure', 'info disclosure', 'data leak',
                'sensitive data', 'debug enabled', 'stack trace',
                'error message', 'verbose error'
            ],
            'Token/Credential Leakage': [
                'token leak', 'api key exposed', 'credential leak',
                'secret key', 'password in response', 'bearer token leak'
            ],
            'Sensitive Data Exposure': [
                'pii exposure', 'personal data', 'unencrypted data',
                'plaintext password', 'sensitive information'
            ],
            
            # File Operations
            'File Upload': [
                'file upload', 'unrestricted upload', 'upload vulnerability',
                'arbitrary file upload', 'malicious file'
            ],
            'Path Traversal': [
                'path traversal', 'directory traversal', 'lfi',
                'local file inclusion', '../', 'dot dot slash'
            ],
            
            # Deserialization
            'Deserialization': [
                'deserialization', 'unsafe deserialization', 'pickle',
                'java deserialization', 'object injection'
            ],
            
            # Configuration Issues
            'Exposed Admin Interface': [
                'exposed admin', 'admin panel', 'administrative interface',
                'debug console', 'management interface', '/admin accessible'
            ],
            'CORS Misconfiguration': [
                'cors', 'cors misconfiguration', 'cors bypass',
                'cross-origin', 'access-control-allow-origin'
            ],
            'Weak Cryptography': [
                'weak crypto', 'weak encryption', 'weak cipher',
                'insecure algorithm', 'md5', 'sha1', 'weak key',
                'hardcoded key', 'predictable random'
            ],
            
            # Other Web Attacks
            'CSRF': [
                'csrf', 'cross-site request forgery', 'cross site request',
                'missing csrf', 'no csrf protection'
            ],
            'Clickjacking': [
                'clickjacking', 'ui redressing', 'x-frame-options',
                'iframe injection', 'frame busting'
            ],
            'Open Redirect': [
                'open redirect', 'unvalidated redirect', 'redirect vulnerability',
                'url redirection'
            ],
            'XXE': [
                'xxe', 'xml external entity', 'xml injection',
                'external entity'
            ],
            'Cache Poisoning': [
                'cache poisoning', 'web cache poisoning',
                'cache deception', 'cache key'
            ],
            
            # RCE
            'Remote Code Execution': [
                'rce', 'remote code execution', 'code execution',
                'arbitrary code', 'command execution'
            ]
        }
    
    def extract_vulnerability_type(self, text: str, 
                                   weakness_name: str = "",
                                   cwe_id: int = 0) -> str:
        """
        Extract vulnerability type from text with enhanced detection
        
        Args:
            text: Description or title text
            weakness_name: CWE weakness name
            cwe_id: CWE ID number
            
        Returns:
            Detected vulnerability type
        """
        
        text_lower = text.lower()
        weakness_lower = weakness_name.lower()
        
        # Check CWE mapping first
        if cwe_id:
            vuln_type = self._map_cwe_to_type(cwe_id)
            if vuln_type != 'Other':
                return vuln_type
        
        # Check weakness name
        for vuln_type, keywords in self.type_keywords.items():
            if any(keyword in weakness_lower for keyword in keywords):
                return vuln_type
        
        # Check description text
        # Use scoring to find best match
        scores = {}
        for vuln_type, keywords in self.type_keywords.items():
            score = sum(1 for keyword in keywords if keyword in text_lower)
            if score > 0:
                scores[vuln_type] = score
        
        if scores:
            # Return type with highest score
            return max(scores, key=scores.get)
        
        return 'Other'
    
    def _map_cwe_to_type(self, cwe_id: int) -> str:
        """Enhanced CWE to vulnerability type mapping"""
        
        cwe_mapping = {
            # Access Control
            284: 'IDOR',
            285: 'Broken Authorization',
            287: 'Broken Authentication',
            306: 'Broken Authentication',
            307: 'Broken Authentication',
            
            # Injection
            79: 'XSS',
            89: 'SQL Injection',
            564: 'SQL Injection',
            943: 'NoSQL Injection',
            78: 'Command Injection',
            77: 'Command Injection',
            
            # SSRF and related
            918: 'SSRF',
            611: 'XXE',
            
            # GraphQL
            1321: 'GraphQL Introspection',
            
            # API
            799: 'Excessive Data Exposure',
            770: 'Rate Limiting Issues',
            400: 'API Abuse',
            
            # File operations
            22: 'Path Traversal',
            434: 'File Upload',
            73: 'Path Traversal',
            
            # Deserialization
            502: 'Deserialization',
            
            # CSRF
            352: 'CSRF',
            
            # Cryptography
            326: 'Weak Cryptography',
            327: 'Weak Cryptography',
            328: 'Weak Cryptography',
            916: 'Weak Cryptography',
            
            # Session
            384: 'Session Fixation',
            
            # Information Disclosure
            200: 'Information Disclosure',
            209: 'Information Disclosure',
            
            # Redirect
            601: 'Open Redirect',
            
            # CORS
            942: 'CORS Misconfiguration',
            
            # Clickjacking
            1021: 'Clickjacking',
            
            # Race Condition
            362: 'Race Condition',
            366: 'Race Condition',
            
            # Business Logic
            840: 'Business Logic',
        }
        
        return cwe_mapping.get(cwe_id, 'Other')
    
    def extract_all_types(self, text: str) -> List[str]:
        """Extract ALL matching vulnerability types (not just first match)"""
        
        text_lower = text.lower()
        found_types = set()
        
        for vuln_type, keywords in self.type_keywords.items():
            if any(keyword in text_lower for keyword in keywords):
                found_types.add(vuln_type)
        
        return list(found_types) if found_types else ['Other']
