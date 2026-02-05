# src/features/feature_engineer.py

import pandas as pd
import numpy as np
from typing import List, Dict
from sklearn.preprocessing import LabelEncoder, StandardScaler
from collections import Counter

class FeatureEngineer:
    """
    Transforms raw vulnerability reports into ML-ready features
    """
    
    def __init__(self):
        self.tech_encoder = LabelEncoder()
        self.vuln_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        self.tech_vocab = set()
    
    def fit_transform(self, reports: List[VulnerabilityReport]) -> pd.DataFrame:
        """Transform reports into feature dataframe"""
        
        features = []
        
        for report in reports:
            feature_dict = self._extract_features(report)
            features.append(feature_dict)
        
        df = pd.DataFrame(features)
        
        # Encode categorical variables
        df = self._encode_categoricals(df)
        
        # Create interaction features
        df = self._create_interactions(df)
        
        # Create temporal features
        df = self._create_temporal_features(df)
        
        return df
    
    def _extract_features(self, report: VulnerabilityReport) -> Dict:
        """Extract features from a single report"""
        
        features = {
            # Target features
            'target_company': report.target_company,
            'target_size': self._estimate_company_size(report.target_company),
            
            # Vulnerability features
            'vuln_type': report.vulnerability_type,
            'severity': report.severity,
            'cvss_score': report.cvss_score,
            'complexity': report.complexity,
            
            # Technology features
            'tech_stack_count': len(report.technology_stack),
            'has_javascript_framework': self._has_js_framework(report.technology_stack),
            'has_database': self._has_database(report.technology_stack),
            'has_cloud_service': self._has_cloud(report.technology_stack),
            'primary_language': self._extract_primary_language(report.technology_stack),
            
            # Authentication features
            'auth_required': report.authentication_required,
            'privilege_level': report.privileges_required,
            'user_interaction': report.user_interaction,
            
            # Location features
            'location': report.vulnerability_location,
            'endpoint_depth': self._calculate_endpoint_depth(report.endpoint),
            'http_method': report.http_method,
            
            # Temporal features
            'disclosure_delay_days': (report.disclosed_date - report.reported_date).days,
            'report_year': report.reported_date.year,
            'report_month': report.reported_date.month,
            'report_day_of_week': report.reported_date.weekday(),
            
            # Bounty features
            'bounty_amount': report.bounty_amount,
            'has_bounty': report.bounty_amount > 0,
            
            # Researcher features
            'researcher_reputation': report.researcher_reputation,
            
            # OWASP/CWE features
            'owasp_category': report.owasp_category,
            'cwe_id': report.cwe_id,
            
            # Text features (will be processed separately)
            'description_length': len(report.description),
            'steps_count': len(report.steps_to_reproduce),
            
            # Tags
            'tag_count': len(report.tags),
            'has_authentication_tag': any('auth' in tag.lower() for tag in report.tags),
            'has_authorization_tag': any('author' in tag.lower() for tag in report.tags),
        }
        
        # Technology one-hot encoding
        for tech in ['React', 'Angular', 'Vue.js', 'Node.js', 'Python', 'PHP', 
                     'Java', 'Ruby', 'GraphQL', 'REST', 'MongoDB', 'PostgreSQL', 
                     'MySQL', 'AWS', 'Azure', 'Docker', 'Kubernetes']:
            features[f'tech_{tech.lower().replace(".", "").replace(" ", "_")}'] = \
                tech in report.technology_stack
        
        return features
    
    def _estimate_company_size(self, company_name: str) -> str:
        """Estimate company size category"""
        # This would use external data (employee count, revenue, etc.)
        # For now, simple heuristic
        
        large_companies = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 
                          'netflix', 'uber', 'airbnb', 'twitter', 'linkedin']
        
        if any(large in company_name.lower() for large in large_companies):
            return 'large'
        else:
            return 'small_medium'
    
    def _has_js_framework(self, tech_stack: List[str]) -> bool:
        """Check if has JavaScript framework"""
        js_frameworks = ['React', 'Angular', 'Vue.js', 'Svelte', 'Next.js']
        return any(fw in tech_stack for fw in js_frameworks)
    
    def _has_database(self, tech_stack: List[str]) -> bool:
        """Check if has database"""
        databases = ['MongoDB', 'PostgreSQL', 'MySQL', 'Redis', 'Cassandra']
        return any(db in tech_stack for db in databases)
    
    def _has_cloud(self, tech_stack: List[str]) -> bool:
        """Check if uses cloud services"""
        cloud = ['AWS', 'Azure', 'Google Cloud', 'GCP']
        return any(c in tech_stack for c in cloud)
    
    def _extract_primary_language(self, tech_stack: List[str]) -> str:
        """Extract primary programming language"""
        languages = ['Python', 'Node.js', 'Java', 'Ruby', 'PHP', 'Go', 'C#']
        for lang in languages:
            if lang in tech_stack:
                return lang
        return 'Unknown'
    
    def _calculate_endpoint_depth(self, endpoint: str) -> int:
        """Calculate API endpoint depth"""
        if not endpoint:
            return 0
        return endpoint.count('/')
    
    def _encode_categoricals(self, df: pd.DataFrame) -> pd.DataFrame:
        """Encode categorical variables"""
        
        categorical_columns = [
            'target_company', 'vuln_type', 'severity', 'complexity',
            'privilege_level', 'location', 'http_method', 
            'primary_language', 'owasp_category'
        ]
        
        for col in categorical_columns:
            if col in df.columns:
                df[f'{col}_encoded'] = self.vuln_encoder.fit_transform(df[col].fillna('Unknown'))
        
        return df
    
    def _create_interactions(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create interaction features"""
        
        # Technology × Vulnerability Type
        if 'tech_react' in df.columns and 'vuln_type_encoded' in df.columns:
            df['react_xss_interaction'] = df['tech_react'] * (df['vuln_type'] == 'XSS').astype(int)
        
        # Company Size × Bounty
        if 'target_size' in df.columns and 'bounty_amount' in df.columns:
            df['size_bounty_interaction'] = (df['target_size'] == 'large').astype(int) * df['bounty_amount']
        
        # Authentication × Severity
        if 'auth_required' in df.columns and 'cvss_score' in df.columns:
            df['auth_severity_interaction'] = df['auth_required'].astype(int) * df['cvss_score']
        
        return df
    
    def _create_temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create temporal features"""
        
        # Season
        if 'report_month' in df.columns:
            df['season'] = df['report_month'].apply(lambda m: 
                'winter' if m in [12, 1, 2] else
                'spring' if m in [3, 4, 5] else
                'summer' if m in [6, 7, 8] else 'fall'
            )
        
        # Is weekend
        if 'report_day_of_week' in df.columns:
            df['is_weekend'] = (df['report_day_of_week'] >= 5).astype(int)
        
        return df


class TechnologyStackEncoder:
    """
    Advanced encoding for technology stacks
    Uses embeddings and co-occurrence patterns
    """
    
    def __init__(self, embedding_dim: int = 50):
        self.embedding_dim = embedding_dim
        self.tech_to_idx = {}
        self.embeddings = None
        self.co_occurrence_matrix = None
    
    def fit(self, tech_stacks: List[List[str]]):
        """Learn technology embeddings from co-occurrence"""
        
        # Build vocabulary
        all_techs = set()
        for stack in tech_stacks:
            all_techs.update(stack)
        
        self.tech_to_idx = {tech: idx for idx, tech in enumerate(sorted(all_techs))}
        vocab_size = len(self.tech_to_idx)
        
        # Build co-occurrence matrix
        self.co_occurrence_matrix = np.zeros((vocab_size, vocab_size))
        
        for stack in tech_stacks:
            indices = [self.tech_to_idx[tech] for tech in stack if tech in self.tech_to_idx]
            for i in indices:
                for j in indices:
                    if i != j:
                        self.co_occurrence_matrix[i, j] += 1
        
        # Use SVD to create embeddings
        from sklearn.decomposition import TruncatedSVD
        svd = TruncatedSVD(n_components=min(self.embedding_dim, vocab_size - 1))
        self.embeddings = svd.fit_transform(self.co_occurrence_matrix)
    
    def transform(self, tech_stack: List[str]) -> np.ndarray:
        """Transform tech stack to embedding"""
        
        if not self.embeddings is not None:
            raise ValueError("Must fit before transform")
        
        # Average embeddings of technologies in stack
        stack_embeddings = []
        for tech in tech_stack:
            if tech in self.tech_to_idx:
                idx = self.tech_to_idx[tech]
                stack_embeddings.append(self.embeddings[idx])
        
        if not stack_embeddings:
            return np.zeros(self.embedding_dim)
        
        return np.mean(stack_embeddings, axis=0)
