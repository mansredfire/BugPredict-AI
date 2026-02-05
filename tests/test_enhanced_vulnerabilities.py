"""
Comprehensive test suite for enhanced vulnerability detection
Tests all 40+ vulnerability types and detection accuracy
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.collectors.enhanced_extractor import EnhancedVulnerabilityExtractor
from src.collectors.data_sources import VulnerabilityReport
from src.models.chain_detector import ChainDetector


class TestEnhancedVulnerabilityExtractor:
    """Test enhanced vulnerability type detection"""
    
    @pytest.fixture
    def extractor(self):
        return EnhancedVulnerabilityExtractor()
    
    # ==================== ACCESS CONTROL TESTS ====================
    
    def test_idor_detection(self, extractor):
        """Test IDOR detection"""
        texts = [
            "Insecure direct object reference allows accessing other users' data",
            "IDOR vulnerability in /api/users/{id} endpoint",
            "Broken access control via object reference manipulation"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'IDOR', f"Failed to detect IDOR in: {text}"
    
    def test_broken_authorization_detection(self, extractor):
        """Test Broken Authorization detection"""
        texts = [
            "Authorization bypass allows vertical privilege escalation",
            "Missing authorization check on admin endpoints",
            "Broken authorization in function level access control"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'Broken Authorization', f"Failed to detect in: {text}"
    
    def test_privilege_escalation_detection(self, extractor):
        """Test Privilege Escalation detection"""
        texts = [
            "Privilege escalation to admin via role manipulation",
            "User can escalate privileges by modifying request",
            "Vertical privilege escalation to gain admin access"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'Privilege Escalation', f"Failed to detect in: {text}"
    
    # ==================== AUTHENTICATION TESTS ====================
    
    def test_jwt_vulnerabilities_detection(self, extractor):
        """Test JWT vulnerability detection"""
        texts = [
            "JWT token accepts none algorithm allowing signature bypass",
            "JSON Web Token with weak secret can be forged",
            "JWT algorithm confusion vulnerability"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'JWT Vulnerabilities', f"Failed to detect JWT vuln in: {text}"
    
    def test_session_fixation_detection(self, extractor):
        """Test Session Fixation detection"""
        texts = [
            "Session fixation allows attacker to hijack user sessions",
            "Session ID not regenerated after login",
            "Session token predictable and can be fixed"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'Session Fixation', f"Failed to detect in: {text}"
    
    def test_broken_authentication_detection(self, extractor):
        """Test Broken Authentication detection"""
        texts = [
            "Weak password policy allows brute force attacks",
            "Default credentials accepted on admin panel",
            "Broken authentication allows credential stuffing"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'Broken Authentication', f"Failed to detect in: {text}"
    
    # ==================== INJECTION TESTS ====================
    
    def test_sql_injection_detection(self, extractor):
        """Test SQL Injection detection"""
        texts = [
            "SQL injection in login form allows database access",
            "Time-based blind SQL injection in search parameter",
            "UNION-based SQLi vulnerability"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'SQL Injection', f"Failed to detect SQLi in: {text}"
    
    def test_nosql_injection_detection(self, extractor):
        """Test NoSQL Injection detection"""
        texts = [
            "NoSQL injection in MongoDB query allows data extraction",
            "MongoDB operator injection via $where clause",
            "NoSQL injection using JSON operator manipulation"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'NoSQL Injection', f"Failed to detect NoSQL injection in: {text}"
    
    def test_command_injection_detection(self, extractor):
        """Test Command Injection detection"""
        texts = [
            "OS command injection allows arbitrary code execution",
            "Shell injection in file processing endpoint",
            "Command injection via user input"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'Command Injection', f"Failed to detect in: {text}"
    
    def test_graphql_injection_detection(self, extractor):
        """Test GraphQL Injection detection"""
        texts = [
            "GraphQL injection allows malicious query execution",
            "GraphQL mutation injection vulnerability",
            "SQL injection through GraphQL query"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'GraphQL Injection', f"Failed to detect in: {text}"
    
    # ==================== XSS TESTS ====================
    
    def test_xss_detection(self, extractor):
        """Test XSS detection (all types)"""
        texts = [
            "Reflected XSS in search parameter",
            "Stored cross-site scripting in comment field",
            "DOM-based XSS vulnerability",
            "Universal XSS affecting all pages"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'XSS', f"Failed to detect XSS in: {text}"
    
    # ==================== SSRF & CLOUD TESTS ====================
    
    def test_ssrf_detection(self, extractor):
        """Test SSRF detection"""
        texts = [
            "Server-side request forgery allows internal network scanning",
            "SSRF vulnerability in URL fetch endpoint",
            "Blind SSRF via image upload"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'SSRF', f"Failed to detect SSRF in: {text}"
    
    def test_cloud_misconfiguration_detection(self, extractor):
        """Test Cloud Misconfiguration detection"""
        texts = [
            "AWS metadata endpoint accessible via SSRF",
            "Cloud misconfiguration exposes 169.254.169.254",
            "Azure instance metadata can be accessed",
            "GCP misconfiguration allows credential theft"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'Cloud Misconfiguration', f"Failed to detect in: {text}"
    
    def test_s3_bucket_exposure_detection(self, extractor):
        """Test S3 Bucket Exposure detection"""
        texts = [
            "Public S3 bucket exposes sensitive data",
            "AWS S3 misconfiguration allows unauthorized access",
            "Exposed S3 bucket with customer data"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'S3 Bucket Exposure', f"Failed to detect in: {text}"
    
    # ==================== API SECURITY TESTS ====================
    
    def test_api_abuse_detection(self, extractor):
        """Test API Abuse detection"""
        texts = [
            "API endpoint abuse allows data scraping",
            "REST API vulnerability enables mass data extraction",
            "API abuse via automated requests"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'API Abuse', f"Failed to detect in: {text}"
    
    def test_excessive_data_exposure_detection(self, extractor):
        """Test Excessive Data Exposure detection"""
        texts = [
            "API returns excessive data including sensitive fields",
            "Mass assignment vulnerability exposes internal data",
            "Over-fetching in GraphQL query reveals PII",
            "Unnecessary data exposure in API response"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'Excessive Data Exposure', f"Failed to detect in: {text}"
    
    def test_rate_limiting_detection(self, extractor):
        """Test Rate Limiting Issues detection"""
        texts = [
            "No rate limiting allows brute force attacks",
            "Missing rate limit on authentication endpoint",
            "Unlimited requests possible on API",
            "Rate limiting bypass via header manipulation"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'Rate Limiting Issues', f"Failed to detect in: {text}"
    
    def test_graphql_introspection_detection(self, extractor):
        """Test GraphQL Introspection detection"""
        texts = [
            "GraphQL introspection enabled exposing schema",
            "Exposed GraphQL schema via __schema query",
            "GraphQL introspection reveals internal API structure"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'GraphQL Introspection', f"Failed to detect in: {text}"
    
    def test_graphql_batching_detection(self, extractor):
        """Test GraphQL Batching Abuse detection"""
        texts = [
            "GraphQL batching attack causes DoS",
            "Nested GraphQL queries exhaust server resources",
            "GraphQL batch query abuse vulnerability"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'GraphQL Batching Abuse', f"Failed to detect in: {text}"
    
    # ==================== BUSINESS LOGIC TESTS ====================
    
    def test_business_logic_detection(self, extractor):
        """Test Business Logic detection"""
        texts = [
            "Business logic flaw allows payment bypass",
            "Price manipulation via workflow bypass",
            "Logic flaw in discount calculation",
            "Coupon abuse via business logic vulnerability"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'Business Logic', f"Failed to detect in: {text}"
    
    def test_race_condition_detection(self, extractor):
        """Test Race Condition detection"""
        texts = [
            "Race condition allows double spending",
            "TOCTOU vulnerability in payment processing",
            "Concurrent requests exploit race condition",
            "Timing attack via parallel processing"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'Race Condition', f"Failed to detect in: {text}"
    
    def test_webhook_abuse_detection(self, extractor):
        """Test Webhook Abuse detection"""
        texts = [
            "Webhook abuse allows SSRF attacks",
            "Webhook injection vulnerability",
            "Callback manipulation via webhook"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'Webhook Abuse', f"Failed to detect in: {text}"
    
    # ==================== CONFIGURATION TESTS ====================
    
    def test_cors_misconfiguration_detection(self, extractor):
        """Test CORS Misconfiguration detection"""
        texts = [
            "CORS misconfiguration allows cross-origin attacks",
            "Wildcard Access-Control-Allow-Origin header",
            "CORS vulnerability with null origin"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'CORS Misconfiguration', f"Failed to detect in: {text}"
    
    def test_exposed_admin_detection(self, extractor):
        """Test Exposed Admin Interface detection"""
        texts = [
            "Exposed admin panel accessible without authentication",
            "Administrative interface publicly accessible",
            "Debug console exposed on production",
            "/admin endpoint unprotected"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'Exposed Admin Interface', f"Failed to detect in: {text}"
    
    def test_weak_cryptography_detection(self, extractor):
        """Test Weak Cryptography detection"""
        texts = [
            "Weak encryption using MD5 hash",
            "SHA1 used for password hashing",
            "Weak cipher suite allows decryption",
            "Hardcoded encryption key in source code",
            "Predictable random number generation"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'Weak Cryptography', f"Failed to detect in: {text}"
    
    # ==================== WEB ATTACK TESTS ====================
    
    def test_csrf_detection(self, extractor):
        """Test CSRF detection"""
        texts = [
            "Cross-site request forgery on state-changing operation",
            "Missing CSRF token on form submission",
            "CSRF vulnerability allows unauthorized actions"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'CSRF', f"Failed to detect CSRF in: {text}"
    
    def test_clickjacking_detection(self, extractor):
        """Test Clickjacking detection"""
        texts = [
            "Clickjacking vulnerability due to missing X-Frame-Options",
            "UI redressing attack possible via iframe",
            "Frameable response allows clickjacking"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'Clickjacking', f"Failed to detect in: {text}"
    
    def test_open_redirect_detection(self, extractor):
        """Test Open Redirect detection"""
        texts = [
            "Open redirect vulnerability in logout endpoint",
            "Unvalidated redirect allows phishing attacks",
            "URL redirection to arbitrary domain"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'Open Redirect', f"Failed to detect in: {text}"
    
    def test_xxe_detection(self, extractor):
        """Test XXE detection"""
        texts = [
            "XML external entity injection allows file read",
            "XXE vulnerability in XML parser",
            "External entity expansion attack"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'XXE', f"Failed to detect XXE in: {text}"
    
    def test_cache_poisoning_detection(self, extractor):
        """Test Cache Poisoning detection"""
        texts = [
            "Web cache poisoning via Host header",
            "Cache key manipulation allows poisoning",
            "HTTP cache poisoning vulnerability"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'Cache Poisoning', f"Failed to detect in: {text}"
    
    def test_host_header_injection_detection(self, extractor):
        """Test Host Header Injection detection"""
        texts = [
            "Host header injection in password reset",
            "Host header poisoning vulnerability",
            "Cache poisoning via Host header manipulation"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'Host Header Injection', f"Failed to detect in: {text}"
    
    # ==================== FILE OPERATION TESTS ====================
    
    def test_file_upload_detection(self, extractor):
        """Test File Upload detection"""
        texts = [
            "Unrestricted file upload allows arbitrary file types",
            "File upload vulnerability enables web shell upload",
            "Arbitrary file upload without validation"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'File Upload', f"Failed to detect in: {text}"
    
    def test_path_traversal_detection(self, extractor):
        """Test Path Traversal detection"""
        texts = [
            "Path traversal via ../ allows arbitrary file read",
            "Directory traversal vulnerability",
            "Local file inclusion using path traversal"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'Path Traversal', f"Failed to detect in: {text}"
    
    # ==================== CODE EXECUTION TESTS ====================
    
    def test_deserialization_detection(self, extractor):
        """Test Deserialization detection"""
        texts = [
            "Unsafe deserialization leads to RCE",
            "Java deserialization vulnerability",
            "Insecure deserialization of user input",
            "Python pickle deserialization exploit"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'Deserialization', f"Failed to detect in: {text}"
    
    def test_rce_detection(self, extractor):
        """Test RCE detection"""
        texts = [
            "Remote code execution via template injection",
            "RCE vulnerability allows arbitrary code",
            "Code execution on server"
        ]
        
        for text in texts:
            result = extractor.extract_vulnerability_type(text)
            assert result == 'Remote Code Execution', f"Failed to detect RCE in: {text}"
    
    # ==================== CWE MAPPING TESTS ====================
    
    def test_cwe_mapping(self, extractor):
        """Test CWE to vulnerability type mapping"""
        
        cwe_tests = [
            (79, 'XSS'),
            (89, 'SQL Injection'),
            (943, 'NoSQL Injection'),
            (78, 'Command Injection'),
            (918, 'SSRF'),
            (611, 'XXE'),
            (284, 'IDOR'),
            (352, 'CSRF'),
            (362, 'Race Condition'),
            (502, 'Deserialization'),
            (434, 'File Upload'),
            (22, 'Path Traversal'),
            (347, 'JWT Vulnerabilities'),
            (770, 'Rate Limiting Issues'),
            (799, 'Excessive Data Exposure'),
            (942, 'CORS Misconfiguration'),
            (1021, 'Clickjacking'),
            (601, 'Open Redirect'),
        ]
        
        for cwe_id, expected_type in cwe_tests:
            result = extractor.extract_vulnerability_type('', '', cwe_id)
            assert result == expected_type, f"CWE-{cwe_id} should map to {expected_type}, got {result}"
    
    # ==================== MULTI-TYPE DETECTION TESTS ====================
    
    def test_extract_all_types(self, extractor):
        """Test extracting multiple vulnerability types from complex text"""
        
        text = """
        This vulnerability chain involves SQL injection to extract credentials,
        then SSRF to access cloud metadata at 169.254.169.254, followed by
        privilege escalation to gain admin access. The GraphQL introspection
        also reveals the schema.
        """
        
        types = extractor.extract_all_types(text)
        
        expected_types = ['SQL Injection', 'SSRF', 'Cloud Misconfiguration', 
                         'Privilege Escalation', 'GraphQL Introspection']
        
        for expected in expected_types:
            assert expected in types, f"Failed to detect {expected} in multi-type text"
    
    def test_category_mapping(self, extractor):
        """Test vulnerability category classification"""
        
        category_tests = [
            ('IDOR', 'Access Control'),
            ('SQL Injection', 'Injection'),
            ('JWT Vulnerabilities', 'Authentication'),
            ('SSRF', 'SSRF & Cloud'),
            ('API Abuse', 'API Security'),
            ('Business Logic', 'Business Logic'),
            ('Weak Cryptography', 'Configuration'),
            ('File Upload', 'File Operations'),
            ('Remote Code Execution', 'Code Execution'),
            ('CSRF', 'Web Attacks'),
        ]
        
        for vuln_type, expected_category in category_tests:
            category = extractor.get_vuln_category(vuln_type)
            assert category == expected_category, \
                f"{vuln_type} should be in {expected_category}, got {category}"


class TestEnhancedChainDetector:
    """Test enhanced chain detection with new vulnerability types"""
    
    @pytest.fixture
    def detector(self):
        return ChainDetector()
    
    def test_jwt_chain_detection(self, detector):
        """Test JWT vulnerability chain detection"""
        
        vulns = ['JWT Vulnerabilities', 'Broken Authentication', 'IDOR']
        chains = detector.detect_chains(vulns)
        
        jwt_chains = [c for c in chains if 'JWT' in c['name']]
        assert len(jwt_chains) > 0, "Failed to detect JWT account takeover chain"
        
        chain = jwt_chains[0]
        assert chain['severity'] == 'critical'
        assert all(v in chain['vulns'] for v in vulns)
    
    def test_cloud_metadata_chain_detection(self, detector):
        """Test cloud metadata exploitation chain"""
        
        vulns = ['SSRF', 'Cloud Misconfiguration', 'S3 Bucket Exposure']
        chains = detector.detect_chains(vulns)
        
        cloud_chains = [c for c in chains if 'Cloud' in c['name'] or 'Metadata' in c['name']]
        assert len(cloud_chains) > 0, "Failed to detect cloud metadata chain"
        
        chain = cloud_chains[0]
        assert chain['severity'] == 'critical'
        assert chain['likelihood'] >= 0.8
    
    def test_graphql_introspection_chain(self, detector):
        """Test GraphQL introspection to data breach chain"""
        
        vulns = ['GraphQL Introspection', 'Excessive Data Exposure', 'IDOR']
        chains = detector.detect_chains(vulns)
        
        graphql_chains = [c for c in chains if 'GraphQL' in c['name']]
        assert len(graphql_chains) > 0, "Failed to detect GraphQL chain"
        
        chain = graphql_chains[0]
        assert 'data' in chain['impact'].lower() or 'database' in chain['impact'].lower()
    
    def test_rate_limit_chain_detection(self, detector):
        """Test rate limiting bypass chain"""
        
        vulns = ['Rate Limiting Issues', 'Broken Authentication', 'IDOR']
        chains = detector.detect_chains(vulns)
        
        rate_chains = [c for c in chains if 'Rate' in c['name']]
        assert len(rate_chains) > 0, "Failed to detect rate limit bypass chain"
    
    def test_race_condition_chain_detection(self, detector):
        """Test race condition exploitation chains"""
        
        vulns = ['Race Condition', 'Business Logic', 'Broken Authorization']
        chains = detector.detect_chains(vulns)
        
        race_chains = [c for c in chains if 'Race' in c['name']]
        assert len(race_chains) > 0, "Failed to detect race condition chain"
    
    def test_nosql_injection_chain(self, detector):
        """Test NoSQL injection to RCE chain"""
        
        vulns = ['NoSQL Injection', 'Command Injection', 'Remote Code Execution']
        chains = detector.detect_chains(vulns)
        
        nosql_chains = [c for c in chains if 'NoSQL' in c['name']]
        assert len(nosql_chains) > 0, "Failed to detect NoSQL injection chain"
        
        chain = nosql_chains[0]
        assert chain['severity'] == 'critical'
    
    def test_webhook_ssrf_chain(self, detector):
        """Test webhook to SSRF chain"""
        
        vulns = ['Webhook Abuse', 'SSRF', 'Cloud Misconfiguration']
        chains = detector.detect_chains(vulns)
        
        webhook_chains = [c for c in chains if 'Webhook' in c['name']]
        assert len(webhook_chains) > 0, "Failed to detect webhook SSRF chain"
    
    def test_cors_credential_theft_chain(self, detector):
        """Test CORS to credential theft chain"""
        
        vulns = ['CORS Misconfiguration', 'Information Disclosure', 'Token/Credential Leakage']
        chains = detector.detect_chains(vulns)
        
        cors_chains = [c for c in chains if 'CORS' in c['name']]
        assert len(cors_chains) > 0, "Failed to detect CORS credential theft chain"
    
    def test_partial_chain_detection(self, detector):
        """Test partial chain detection (missing prerequisites)"""
        
        # Only 2 out of 3 required vulnerabilities
        vulns = ['SSRF', 'Cloud Misconfiguration']
        chains = detector.detect_chains(vulns)
        
        # Should detect partial chains for high/critical severity
        partial_chains = [c for c in chains if c.get('partial', False)]
        
        if partial_chains:
            chain = partial_chains[0]
            assert 'missing_prerequisites' in chain
            assert len(chain['missing_prerequisites']) > 0
    
    def test_chain_scoring(self, detector):
        """Test chain exploitability scoring"""
        
        vulns = ['SSRF', 'Cloud Misconfiguration', 'S3 Bucket Exposure']
        chains = detector.detect_chains(vulns)
        
        assert len(chains) > 0, "No chains detected"
        
        for chain in chains:
            # Score should be between 0 and 10
            assert 0 <= chain['exploitability_score'] <= 10
            
            # Critical chains should have higher scores
            if chain['severity'] == 'critical':
                assert chain['exploitability_score'] >= 5.0
    
    def test_chain_ranking(self, detector):
        """Test chain ranking by exploitability"""
        
        vulns = ['XSS', 'CSRF', 'SSRF', 'Cloud Misconfiguration', 
                'JWT Vulnerabilities', 'Broken Authentication', 'IDOR']
        
        chains = detector.detect_chains(vulns)
        ranked = detector.rank_chains(chains)
        
        # Check that chains are ranked (have rank field)
        for i, chain in enumerate(ranked, 1):
            assert chain['rank'] == i
        
        # Check that they're sorted by score
        for i in range(len(ranked) - 1):
            assert ranked[i]['exploitability_score'] >= ranked[i+1]['exploitability_score']
    
    def test_attack_path_generation(self, detector):
        """Test attack path discovery"""
        
        vulns = ['IDOR', 'Information Disclosure', 'SSRF', 'Remote Code Execution']
        paths = detector.find_attack_paths(vulns, max_length=4)
        
        assert len(paths) > 0, "No attack paths found"
        
        # Verify paths are valid
        for path in paths:
            assert len(path) >= 2, "Path too short"
            assert all(v in vulns for v in path), "Invalid vulnerability in path"
    
    def test_chain_statistics(self, detector):
        """Test chain statistics calculation"""
        
        vulns = ['SSRF', 'Cloud Misconfiguration', 'S3 Bucket Exposure',
                'GraphQL Introspection', 'IDOR', 'Rate Limiting Issues']
        
        detector.detect_chains(vulns)
        stats = detector.get_chain_statistics()
        
        assert 'total_chains' in stats
        assert 'critical_chains' in stats
        assert 'high_chains' in stats
        assert 'avg_score' in stats
        
        if stats['total_chains'] > 0:
            assert stats['avg_score'] > 0
            assert stats['critical_chains'] + stats['high_chains'] <= stats['total_chains']


class TestIntegration:
    """Integration tests for complete vulnerability analysis flow"""
    
    def test_end_to_end_detection(self):
        """Test complete vulnerability detection pipeline"""
        
        extractor = EnhancedVulnerabilityExtractor()
        detector = ChainDetector()
        
        # Simulate a complex vulnerability report
        text = """
        Found multiple vulnerabilities in the API:
        1. GraphQL introspection reveals internal schema
        2. No rate limiting on authentication endpoints
        3. IDOR allows access to other users' data
        4. JWT tokens can be forged using none algorithm
        5. CORS misconfiguration with wildcard origin
        """
        
        # Extract all vulnerability types
        vuln_types = extractor.extract_all_types(text)
        
        # Should detect multiple types
        assert len(vuln_types) >= 4
        assert 'GraphQL Introspection' in vuln_types
        assert 'Rate Limiting Issues' in vuln_types
        assert 'IDOR' in vuln_types
        assert 'JWT Vulnerabilities' in vuln_types
        
        # Detect chains
        chains = detector.detect_chains(vuln_types)
        
        # Should detect at least one chain
        assert len(chains) > 0
        
        # Verify chain contains expected vulnerabilities
        chain = chains[0]
        assert 'exploitability_score' in chain
        assert 'severity' in chain
        assert 'steps' in chain
    
    def test_realistic_report_processing(self):
        """Test processing a realistic vulnerability report"""
        
        # Create a realistic report
        report = VulnerabilityReport(
            report_id='TEST-001',
            platform='test',
            target_domain='example.com',
            target_company='Example Corp',
            target_program='Bug Bounty',
            vulnerability_type='Other',  # Will be detected
            severity='high',
            cvss_score=7.5,
            technology_stack=['React', 'Node.js', 'MongoDB'],
            endpoint='/api/graphql',
            http_method='POST',
            vulnerability_location='api',
            description="""
            The GraphQL API has introspection enabled, allowing attackers to enumerate
            the entire schema. Combined with the lack of rate limiting, this enables
            mass data extraction via automated queries. Additionally, the API returns
            excessive data in responses, including sensitive user information.
            """,
            steps_to_reproduce=[
                'Send introspection query to /api/graphql',
                'Enumerate all available queries and mutations',
                'Craft batch queries to extract data',
                'Execute unlimited requests due to missing rate limits'
            ],
            impact='Complete database enumeration and data breach',
            remediation='Disable introspection, implement rate limiting, filter response data',
            reported_date=datetime.now(),
            disclosed_date=datetime.now(),
            bounty_amount=5000.0,
            researcher_reputation=500,
            authentication_required=False,
            privileges_required='none',
            user_interaction=False,
            complexity='low',
            tags=['graphql', 'api', 'data-leak'],
            owasp_category='API3:2023',
            cwe_id=1321,
            raw_data={}
        )
        
        # Extract vulnerability type
        extractor = EnhancedVulnerabilityExtractor()
        vuln_type = extractor.extract_vulnerability_type(
            report.description,
            '',
            report.cwe_id
        )
        
        # Should detect GraphQL Introspection
        assert vuln_type in ['GraphQL Introspection', 'Excessive Data Exposure', 'API Abuse']
        
        # Extract all types
        all_types = extractor.extract_all_types(report.description)
        
        # Should detect multiple related vulnerabilities
        assert 'GraphQL Introspection' in all_types or 'API Abuse' in all_types
        assert 'Rate Limiting Issues' in all_types
        assert 'Excessive Data Exposure' in all_types


# ==================== PERFORMANCE TESTS ====================

class TestPerformance:
    """Test performance of enhanced detection"""
    
    def test_extraction_performance(self):
        """Test extraction speed"""
        import time
        
        extractor = EnhancedVulnerabilityExtractor()
        
        test_texts = [
            "SQL injection in login form",
            "NoSQL injection in MongoDB query",
            "GraphQL introspection enabled",
            "SSRF to cloud metadata endpoint",
            "JWT none algorithm accepted",
        ] * 100  # 500 total tests
        
        start = time.time()
        
        for text in test_texts:
            extractor.extract_vulnerability_type(text)
        
        elapsed = time.time() - start
        
        # Should process 500 texts in under 1 second
        assert elapsed < 1.0, f"Too slow: {elapsed:.2f}s for 500 extractions"
        
        print(f"\nPerformance: {len(test_texts)/elapsed:.0f} extractions/second")
    
    def test_chain_detection_performance(self):
        """Test chain detection speed"""
        import time
        
        detector = ChainDetector()
        
        vulns = ['SSRF', 'Cloud Misconfiguration', 'S3 Bucket Exposure',
                'GraphQL Introspection', 'IDOR', 'Rate Limiting Issues',
                'JWT Vulnerabilities', 'XSS', 'CSRF', 'SQL Injection']
        
        start = time.time()
        
        for _ in range(100):
            detector.detect_chains(vulns)
        
        elapsed = time.time() - start
        
        # Should detect chains 100 times in under 1 second
        assert elapsed < 1.0, f"Too slow: {elapsed:.2f}s for 100 detections"
        
        print(f"Chain detection: {100/elapsed:.0f} detections/second")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
