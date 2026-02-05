"""Enhanced vulnerability type extraction with comprehensive coverage"""

from typing import List, Dict, Optional
import re


class EnhancedVulnerabilityExtractor:
    """
    Enhanced vulnerability type detection
    Covers 40+ vulnerability types including:
    - Modern API vulnerabilities
    - Cloud misconfigurations
    - GraphQL issues
    - Race conditions
    - Advanced authentication issues
    - And more
    """
    
    def __init__(self):
        self.type_keywords = self._build_keyword_mapping()
        self.cwe_mapping = self._build_cwe_mapping()
    
    def _build_keyword_mapping(self) -> Dict[str, List[str]]:
        """Build comprehensive keyword mapping for all vulnerability types"""
        
        return {
            # ==================== ACCESS CONTROL ====================
            'IDOR': [
                'idor', 'insecure direct object', 'broken access control',
                'unauthorized access', 'object reference', 'resource manipulation',
                'direct object reference', 'object level authorization'
            ],
            
            'Broken Authorization': [
                'authorization bypass', 'broken authorization', 'missing authorization',
                'vertical privilege', 'horizontal privilege', 'function level',
                'missing access control', 'improper authorization', 'authorization flaw'
            ],
            
            'Privilege Escalation': [
                'privilege escalation', 'privesc', 'escalate privileges',
                'elevate privileges', 'gain admin', 'become admin', 'vertical escalation',
                'horizontal escalation', 'elevation of privilege'
            ],
            
            'Broken Access Control': [
                'broken access control', 'access control bypass', 'missing access control',
                'improper access control', 'inadequate access control'
            ],
            
            # ==================== AUTHENTICATION ====================
            'Authentication Bypass': [
                'auth bypass', 'authentication bypass', 'login bypass',
                'bypass authentication', 'authentication circumvention'
            ],
            
            'Broken Authentication': [
                'broken authentication', 'weak password', 'default credentials',
                'credential stuffing', 'password spray', 'brute force',
                'weak authentication', 'authentication flaw', 'improper authentication'
            ],
            
            'Session Fixation': [
                'session fixation', 'session hijacking', 'session token manipulation',
                'session id predictable', 'session management flaw'
            ],
            
            'JWT Vulnerabilities': [
                'jwt', 'json web token', 'jwt none algorithm', 'jwt signature bypass',
                'jwt weak secret', 'jwt manipulation', 'jwt header injection',
                'jwt algorithm confusion', 'jwt kid injection'
            ],
            
            'Account Takeover': [
                'account takeover', 'ato', 'account compromise', 'user account takeover',
                'account hijacking'
            ],
            
            # ==================== INJECTION ATTACKS ====================
            'SQL Injection': [
                'sql injection', 'sqli', 'sql', 'union select', 'blind sql',
                'time-based sql', 'error-based sql', 'boolean sql', 'second order sql',
                'out-of-band sql', 'stacked queries'
            ],
            
            'NoSQL Injection': [
                'nosql injection', 'nosql', 'mongodb injection', 'mongo injection',
                'cassandra injection', 'couchdb injection', 'operator injection',
                'nosql operator', '$where injection', 'json injection'
            ],
            
            'Command Injection': [
                'command injection', 'os command', 'shell injection', 'cmd injection',
                'code injection', 'rce via command', 'os injection', 'blind command injection'
            ],
            
            'GraphQL Injection': [
                'graphql injection', 'graphql mutation injection', 'graphql query injection',
                'graphql sql injection', 'graphql command injection'
            ],
            
            'Host Header Injection': [
                'host header injection', 'host header poisoning', 'host injection',
                'host header manipulation', 'cache poisoning via host', 'password reset poisoning'
            ],
            
            'HTTP Parameter Pollution': [
                'hpp', 'http parameter pollution', 'parameter pollution',
                'parameter tampering', 'parameter injection', 'query pollution'
            ],
            
            # ==================== XSS VARIANTS ====================
            'XSS': [
                'xss', 'cross-site scripting', 'cross site scripting',
                'reflected xss', 'stored xss', 'dom xss', 'dom-based xss',
                'self xss', 'blind xss', 'universal xss', 'mutation xss', 'mxss'
            ],
            
            # ==================== SSRF AND CLOUD ====================
            'SSRF': [
                'ssrf', 'server-side request forgery', 'server side request',
                'internal port scan', 'internal network access', 'blind ssrf',
                'out-of-band ssrf'
            ],
            
            'Cloud Misconfiguration': [
                'cloud misconfiguration', 'aws misconfiguration', 'azure misconfiguration',
                'gcp misconfiguration', 'metadata endpoint', '169.254.169.254',
                'cloud metadata', 'imds', 'instance metadata', 'cloud credential leak'
            ],
            
            'S3 Bucket Exposure': [
                's3 bucket', 'exposed s3', 'public bucket', 's3 misconfiguration',
                'aws s3 leak', 'bucket enumeration', 's3 acl', 'open s3'
            ],
            
            # ==================== API SECURITY ====================
            'API Abuse': [
                'api abuse', 'api misuse', 'api endpoint abuse', 'rest api abuse',
                'api vulnerability', 'api exploitation', 'api scraping'
            ],
            
            'Excessive Data Exposure': [
                'excessive data', 'mass assignment', 'over-fetching', 'api data leak',
                'unnecessary data exposure', 'verbose response', 'information leakage',
                'data over-exposure', 'excessive information'
            ],
            
            'Rate Limiting Issues': [
                'rate limit', 'rate limiting', 'brute force possible', 'no rate limit',
                'missing rate limit', 'unlimited requests', 'dos via', 'resource exhaustion',
                'request flooding', 'missing throttling', 'abuse via volume'
            ],
            
            'GraphQL Introspection': [
                'graphql introspection', 'exposed schema', 'graphql schema leak',
                'introspection enabled', '__schema', 'graphql discovery',
                'schema enumeration'
            ],
            
            'GraphQL Batching Abuse': [
                'graphql batching', 'batch attack', 'graphql query batching',
                'batched queries', 'nested queries', 'graphql dos', 'query complexity'
            ],
            
            # ==================== BUSINESS LOGIC ====================
            'Business Logic': [
                'business logic', 'logic flaw', 'workflow bypass', 'payment bypass',
                'discount abuse', 'price manipulation', 'quantity manipulation',
                'coupon abuse', 'refund abuse', 'voucher abuse', 'loyalty points'
            ],
            
            'Race Condition': [
                'race condition', 'race condition attack', 'toctou', 'time of check',
                'concurrent request', 'parallel request', 'double spending',
                'parallel processing', 'race window', 'timing attack'
            ],
            
            'Webhook Abuse': [
                'webhook', 'webhook abuse', 'webhook injection', 'webhook bypass',
                'callback manipulation', 'webhook spoofing', 'webhook validation'
            ],
            
            # ==================== DATA EXPOSURE ====================
            'Information Disclosure': [
                'information disclosure', 'info disclosure', 'data leak', 'debug enabled',
                'stack trace', 'error message', 'verbose error', 'information leakage',
                'sensitive information', 'data exposure'
            ],
            
            'Token/Credential Leakage': [
                'token leak', 'api key exposed', 'credential leak', 'secret key',
                'password in response', 'bearer token leak', 'access token leak',
                'refresh token', 'api key in response', 'hardcoded credentials'
            ],
            
            'Sensitive Data Exposure': [
                'pii exposure', 'personal data', 'unencrypted data', 'plaintext password',
                'sensitive information', 'gdpr violation', 'pci violation',
                'personal information', 'customer data leak'
            ],
            
            # ==================== FILE OPERATIONS ====================
            'File Upload': [
                'file upload', 'unrestricted upload', 'upload vulnerability',
                'arbitrary file upload', 'malicious file', 'file upload bypass',
                'unrestricted file upload', 'file extension bypass'
            ],
            
            'Path Traversal': [
                'path traversal', 'directory traversal', 'lfi', 'local file inclusion',
                '../', 'dot dot slash', '..\\', 'file inclusion', 'arbitrary file read'
            ],
            
            # ==================== DESERIALIZATION & RCE ====================
            'Deserialization': [
                'deserialization', 'unsafe deserialization', 'pickle', 'insecure deserialization',
                'java deserialization', 'object injection', 'php deserialization',
                'yaml deserialization'
            ],
            
            'Remote Code Execution': [
                'rce', 'remote code execution', 'code execution', 'arbitrary code',
                'command execution', 'remote execution', 'arbitrary code execution'
            ],
            
            # ==================== CONFIGURATION ISSUES ====================
            'Exposed Admin Interface': [
                'exposed admin', 'admin panel', 'administrative interface',
                'debug console', 'management interface', '/admin accessible',
                'admin portal exposed', 'unprotected admin'
            ],
            
            'CORS Misconfiguration': [
                'cors', 'cors misconfiguration', 'cors bypass', 'cross-origin',
                'access-control-allow-origin', 'cors wildcard', 'null origin',
                'cors vulnerability'
            ],
            
            'Weak Cryptography': [
                'weak crypto', 'weak encryption', 'weak cipher', 'insecure algorithm',
                'md5', 'sha1', 'weak key', 'hardcoded key', 'predictable random',
                'weak hash', 'broken cryptography', 'insecure cryptographic'
            ],
            
            # ==================== WEB ATTACKS ====================
            'CSRF': [
                'csrf', 'cross-site request forgery', 'cross site request',
                'missing csrf', 'no csrf protection', 'csrf token bypass',
                'state-changing operation'
            ],
            
            'Clickjacking': [
                'clickjacking', 'ui redressing', 'x-frame-options', 'iframe injection',
                'frame busting', 'frameable response', 'iframe abuse'
            ],
            
            'Open Redirect': [
                'open redirect', 'unvalidated redirect', 'redirect vulnerability',
                'url redirection', 'redirect bypass', 'arbitrary redirect'
            ],
            
            'XXE': [
                'xxe', 'xml external entity', 'xml injection', 'external entity',
                'xml parser', 'xml entity expansion', 'billion laughs'
            ],
            
            'Cache Poisoning': [
                'cache poisoning', 'web cache poisoning', 'cache deception',
                'cache key manipulation', 'cache injection', 'http cache poisoning'
            ],
        }
    
    def _build_cwe_mapping(self) -> Dict[int, str]:
        """Enhanced CWE to vulnerability type mapping"""
        
        return {
            # Access Control
            284: 'IDOR',
            285: 'Broken Authorization',
            639: 'Broken Authorization',
            
            # Authentication
            287: 'Broken Authentication',
            288: 'Broken Authentication',
            306: 'Broken Authentication',
            307: 'Broken Authentication',
            384: 'Session Fixation',
            
            # Injection
            79: 'XSS',
            89: 'SQL Injection',
            564: 'SQL Injection',
            943: 'NoSQL Injection',
            78: 'Command Injection',
            77: 'Command Injection',
            88: 'Command Injection',
            
            # SSRF
            918: 'SSRF',
            
            # XXE
            611: 'XXE',
            827: 'XXE',
            
            # GraphQL
            1321: 'GraphQL Introspection',
            
            # API
            799: 'Excessive Data Exposure',
            770: 'Rate Limiting Issues',
            400: 'API Abuse',
            920: 'Excessive Data Exposure',
            
            # File Operations
            22: 'Path Traversal',
