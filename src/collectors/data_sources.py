"""Base data source definitions - Enhanced with all vulnerability types"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class VulnerabilityType(Enum):
    """Comprehensive enumeration of vulnerability types"""
    
    # Injection Attacks
    XSS = "XSS"
    SQL_INJECTION = "SQL Injection"
    NOSQL_INJECTION = "NoSQL Injection"
    COMMAND_INJECTION = "Command Injection"
    XXE = "XXE"
    
    # Access Control
    IDOR = "IDOR"
    BROKEN_ACCESS_CONTROL = "Broken Access Control"
    BROKEN_AUTHORIZATION = "Broken Authorization"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    
    # Authentication
    AUTH_BYPASS = "Authentication Bypass"
    BROKEN_AUTHENTICATION = "Broken Authentication"
    SESSION_FIXATION = "Session Fixation"
    JWT_VULNERABILITIES = "JWT Vulnerabilities"
    
    # API Security
    API_ABUSE = "API Abuse"
    EXCESSIVE_DATA_EXPOSURE = "Excessive Data Exposure"
    RATE_LIMIT_BYPASS = "Rate Limiting Issues"
    GRAPHQL_INJECTION = "GraphQL Injection"
    GRAPHQL_INTROSPECTION = "GraphQL Introspection"
    GRAPHQL_BATCHING = "GraphQL Batching Abuse"
    
    # SSRF and Related
    SSRF = "SSRF"
    CLOUD_MISCONFIGURATION = "Cloud Misconfiguration"
    S3_BUCKET_EXPOSURE = "S3 Bucket Exposure"
    
    # Business Logic
    BUSINESS_LOGIC = "Business Logic"
    RACE_CONDITION = "Race Condition"
    WEBHOOK_ABUSE = "Webhook Abuse"
    
    # Data Exposure
    INFO_DISCLOSURE = "Information Disclosure"
    SENSITIVE_DATA_EXPOSURE = "Sensitive Data Exposure"
    TOKEN_LEAKAGE = "Token/Credential Leakage"
    
    # Configuration Issues
    EXPOSED_ADMIN = "Exposed Admin Interface"
    CORS_MISCONFIGURATION = "CORS Misconfiguration"
    WEAK_CRYPTO = "Weak Cryptography"
    
    # File Operations
    FILE_UPLOAD = "File Upload"
    PATH_TRAVERSAL = "Path Traversal"
    
    # Code Execution
    RCE = "Remote Code Execution"
    DESERIALIZATION = "Deserialization"
    
    # Web Attacks
    CSRF = "CSRF"
    CLICKJACKING = "Clickjacking"
    OPEN_REDIRECT = "Open Redirect"
    HOST_HEADER_INJECTION = "Host Header Injection"
    HTTP_PARAMETER_POLLUTION = "HTTP Parameter Pollution"
    CACHE_POISONING = "Cache Poisoning"
    
    # Account Takeover
    ACCOUNT_TAKEOVER = "Account Takeover"
    
    OTHER = "Other"


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class VulnerabilityReport:
    """Standardized vulnerability report structure"""
    
    # Identifiers
    report_id: str
    platform: str  # hackerone, bugcrowd, nvd, github
    
    # Target Information
    target_domain: str
    target_company: str
    target_program: str
    
    # Vulnerability Details
    vulnerability_type: str
    severity: str
    cvss_score: float
    
    # Technical Details
    technology_stack: List[str] = field(default_factory=list)
    endpoint: str = ""
    http_method: str = "GET"
    vulnerability_location: str = "web"  # web, api, mobile, cloud, other
    
    # Context
    description: str = ""
    steps_to_reproduce: List[str] = field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    
    # Metadata
    reported_date: Optional[datetime] = None
    disclosed_date: Optional[datetime] = None
    bounty_amount: float = 0.0
    researcher_reputation: int = 0
    
    # Additional Features
    authentication_required: bool = False
    privileges_required: str = "none"  # none, low, high
    user_interaction: bool = False
    complexity: str = "medium"  # low, medium, high
    
    # Tags
    tags: List[str] = field(default_factory=list)
    owasp_category: str = ""
    cwe_id: int = 0
    
    # Raw data
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'report_id': self.report_id,
            'platform': self.platform,
            'target_domain': self.target_domain,
            'target_company': self.target_company,
            'target_program': self.target_program,
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'technology_stack': self.technology_stack,
            'endpoint': self.endpoint,
            'http_method': self.http_method,
            'vulnerability_location': self.vulnerability_location,
            'description': self.description,
            'steps_to_reproduce': self.steps_to_reproduce,
            'impact': self.impact,
            'remediation': self.remediation,
            'reported_date': self.reported_date.isoformat() if self.reported_date else None,
            'disclosed_date': self.disclosed_date.isoformat() if self.disclosed_date else None,
            'bounty_amount': self.bounty_amount,
            'researcher_reputation': self.researcher_reputation,
            'authentication_required': self.authentication_required,
            'privileges_required': self.privileges_required,
            'user_interaction': self.user_interaction,
            'complexity': self.complexity,
            'tags': self.tags,
            'owasp_category': self.owasp_category,
            'cwe_id': self.cwe_id
        }


class DataCollector:
    """Base class for data collection with enhanced vulnerability detection"""
    
    def __init__(self, cache_dir: str = "data/cache"):
        self.reports = []
        self.cache_dir = cache_dir
        self._setup_cache()
    
    def _setup_cache(self):
        """Setup caching directory"""
        from pathlib import Path
        Path(self.cache_dir).mkdir(parents=True, exist_ok=True)
    
    def collect(self, limit: int = 1000) -> List[VulnerabilityReport]:
        """Collect vulnerability reports"""
        raise NotImplementedError("Subclasses must implement collect()")
    
    def normalize(self, raw_data: Dict[str, Any]) -> Optional[VulnerabilityReport]:
        """Normalize raw data into standard format"""
        raise NotImplementedError("Subclasses must implement normalize()")
    
    def save_cache(self, reports: List[VulnerabilityReport], filename: str):
        """Save reports to cache"""
        import pickle
        from pathlib import Path
        
        cache_file = Path(self.cache_dir) / filename
        with open(cache_file, 'wb') as f:
            pickle.dump(reports, f)
        
        print(f"Cached {len(reports)} reports to {cache_file}")
    
    def load_cache(self, filename: str) -> Optional[List[VulnerabilityReport]]:
        """Load reports from cache"""
        import pickle
        from pathlib import Path
        
        cache_file = Path(self.cache_dir) / filename
        
        if not cache_file.exists():
            return None
        
        with open(cache_file, 'rb') as f:
            reports = pickle.load(f)
        
        print(f"Loaded {len(reports)} reports from cache")
        return reports
    
    def extract_vulnerability_type(self, text: str, weakness_name: str = "", cwe_id: int = 0) -> str:
        """Extract vulnerability type from text - uses enhanced detector"""
        from .enhanced_extractor import EnhancedVulnerabilityExtractor
        
        extractor = EnhancedVulnerabilityExtractor()
        return extractor.extract_vulnerability_type(text, weakness_name, cwe_id)
    
    def map_severity_to_score(self, severity: str) -> float:
        """Map severity string to CVSS score"""
        
        severity_mapping = {
            'critical': 9.5,
            'high': 7.5,
            'medium': 5.0,
            'low': 3.0,
            'none': 0.0
        }
        
        return severity_mapping.get(severity.lower(), 5.0)
    
    def extract_technologies(self, text: str) -> List[str]:
        """Extract technology stack from text - enhanced version"""
        
        tech_indicators = {
            # Frontend Frameworks
            'React': ['react', 'reactjs', 'react.js', 'react native'],
            'Angular': ['angular', 'angularjs', 'angular.js'],
            'Vue.js': ['vue', 'vuejs', 'vue.js', 'nuxt'],
            'Svelte': ['svelte', 'sveltekit'],
            'Next.js': ['next.js', 'nextjs', 'next js'],
            
            # Backend Frameworks
            'Node.js': ['node', 'nodejs', 'node.js', 'express', 'nestjs', 'koa'],
            'Python': ['python', 'django', 'flask', 'fastapi', 'tornado'],
            'Ruby': ['ruby', 'rails', 'ruby on rails', 'sinatra'],
            'PHP': ['php', 'laravel', 'symfony', 'wordpress', 'codeigniter'],
            'Java': ['java', 'spring', 'spring boot', 'struts', 'hibernate'],
            'Go': ['golang', 'go ', 'gin', 'echo'],
            '.NET': ['asp.net', '.net', 'dotnet', 'c#'],
            
            # APIs
            'GraphQL': ['graphql', 'graph ql', 'apollo'],
            'REST': ['rest api', 'restful', 'rest '],
            'gRPC': ['grpc', 'protocol buffers'],
            'WebSocket': ['websocket', 'ws://'],
            
            # Databases
            'MongoDB': ['mongodb', 'mongo'],
            'PostgreSQL': ['postgresql', 'postgres', 'psql'],
            'MySQL': ['mysql', 'mariadb'],
            'Redis': ['redis'],
            'Cassandra': ['cassandra'],
            'DynamoDB': ['dynamodb', 'dynamo'],
            'Elasticsearch': ['elasticsearch', 'elastic'],
            
            # Cloud
            'AWS': ['aws', 'amazon web services', 's3', 'ec2', 'lambda', 'cloudfront'],
            'Azure': ['azure', 'microsoft azure'],
            'Google Cloud': ['gcp', 'google cloud', 'firebase'],
            'Cloudflare': ['cloudflare', 'cf-'],
            
            # Containers & Orchestration
            'Docker': ['docker', 'container'],
            'Kubernetes': ['kubernetes', 'k8s', 'kubectl'],
            
            # Web Servers
            'Nginx': ['nginx'],
            'Apache': ['apache', 'httpd'],
            'IIS': ['iis', 'internet information services'],
            
            # Authentication
            'OAuth': ['oauth', 'oauth2'],
            'JWT': ['jwt', 'json web token'],
            'SAML': ['saml'],
            
            # Message Queues
            'RabbitMQ': ['rabbitmq', 'rabbit mq'],
            'Kafka': ['kafka', 'apache kafka'],
            
            # Mobile
            'iOS': ['ios', 'swift', 'objective-c'],
            'Android': ['android', 'kotlin'],
            'React Native': ['react native'],
            'Flutter': ['flutter', 'dart'],
        }
        
        text_lower = text.lower()
        technologies = []
        
        for tech, indicators in tech_indicators.items():
            if any(indicator in text_lower for indicator in indicators):
                technologies.append(tech)
        
        return list(set(technologies))
