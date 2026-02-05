"""ML training pipeline - Production Implementation"""

import pandas as pd
import numpy as np
import pickle
import json
from pathlib import Path
from datetime import datetime, timedelta
import logging
from typing import List, Dict, Tuple, Optional
import yaml

from src.collectors.data_sources import VulnerabilityReport
from src.collectors.hackerone_scraper import HackerOneCollector
from src.collectors.bugcrowd_scraper import BugcrowdCollector
from src.collectors.cve_collector import CVECollector
from src.preprocessing.normalizer import DataNormalizer
from src.preprocessing.deduplicator import Deduplicator
from src.preprocessing.enricher import DataEnricher
from src.features.feature_engineer import FeatureEngineer
from src.models.vulnerability_classifier import VulnerabilityPredictor
from src.models.severity_predictor import SeverityPredictor
from src.models.chain_detector import ChainDetector


class TrainingPipeline:
    """
    Complete ML training pipeline for BugPredict AI
    
    Pipeline steps:
    1. Data Collection (HackerOne, Bugcrowd, CVE/NVD)
    2. Data Preprocessing (normalization, deduplication, enrichment)
    3. Feature Engineering (100+ features)
    4. Model Training (ensemble models)
    5. Evaluation & Metrics
    6. Model Persistence
    """
    
    def __init__(self, config_path: str = "config/training_config.yaml"):
        self.config = self._load_config(config_path)
        self.logger = self._setup_logging()
        
        # Data
        self.raw_reports = []
        self.processed_reports = []
        self.features_df = None
        
        # Components
        self.feature_engineer = None
        self.models = {}
        self.metrics = {}
        
        # Paths
        self.data_dir = Path('data')
        self.models_dir = Path('data/models')
        self.results_dir = Path('data/results')
        
        # Create directories
        self.data_dir.mkdir(exist_ok=True)
        self.models_dir.mkdir(exist_ok=True)
        self.results_dir.mkdir(exist_ok=True)
    
    def _load_config(self, config_path: str) -> Dict:
        """Load training configuration"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            return config
        except FileNotFoundError:
            self.logger.warning(f"Config not found: {config_path}, using defaults")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Get default configuration"""
        return {
            'data_collection': {
                'collect_hackerone': True,
                'hackerone_limit': 5000,
                'collect_bugcrowd': True,
                'bugcrowd_limit': 2000,
                'collect_cve': True,
                'cve_start_date': '2020-01-01'
            },
            'preprocessing': {
                'remove_duplicates': True,
                'normalize_text': True,
                'min_report_quality': 0.5
            },
            'training': {
                'test_size': 0.2,
                'validation_size': 0.1,
                'random_state': 42
            },
            'output': {
                'models_dir': 'data/models',
                'save_feature_importance': True
            }
        }
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('training.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)
    
    def run_full_pipeline(self):
        """Execute complete training pipeline"""
        
        self.logger.info("="*70)
        self.logger.info("BUGPREDICT AI TRAINING PIPELINE")
        self.logger.info("="*70)
        
        start_time = datetime.now()
        
        try:
            # Step 1: Data Collection
            self.logger.info("\n[STEP 1/7] Data Collection")
            self.logger.info("-"*70)
            self.raw_reports = self.collect_data()
            self.logger.info(f"✓ Collected {len(self.raw_reports)} vulnerability reports")
            
            if len(self.raw_reports) == 0:
                self.logger.error("No data collected. Aborting pipeline.")
                return
            
            # Step 2: Data Preprocessing
            self.logger.info("\n[STEP 2/7] Data Preprocessing")
            self.logger.info("-"*70)
            self.processed_reports = self.preprocess_data(self.raw_reports)
            self.logger.info(f"✓ Preprocessed {len(self.processed_reports)} reports")
            
            # Step 3: Feature Engineering
            self.logger.info("\n[STEP 3/7] Feature Engineering")
            self.logger.info("-"*70)
            self.features_df = self.engineer_features(self.processed_reports)
            self.logger.info(f"✓ Generated {self.features_df.shape[1]} features")
            
            # Step 4: Train/Test Split
            self.logger.info("\n[STEP 4/7] Data Splitting")
            self.logger.info("-"*70)
            X_train, X_test, y_train, y_test, y_severity, y_cvss = self.split_data(
                self.features_df, 
                self.processed_reports
            )
            
            # Step 5: Model Training
            self.logger.info("\n[STEP 5/7] Model Training")
            self.logger.info("-"*70)
            self.train_models(X_train, X_test, y_train, y_test, y_severity, y_cvss)
            
            # Step 6: Model Evaluation
            self.logger.info("\n[STEP 6/7] Model Evaluation")
            self.logger.info("-"*70)
            self.evaluate_models(X_test, y_test)
            
            # Step 7: Save Everything
            self.logger.info("\n[STEP 7/7] Saving Models & Results")
            self.logger.info("-"*70)
            self.save_models()
            self.save_metrics()
            
            # Training complete
            duration = datetime.now() - start_time
            self.logger.info("\n" + "="*70)
            self.logger.info(f"✓ TRAINING PIPELINE COMPLETED SUCCESSFULLY")
            self.logger.info(f"Duration: {duration}")
            self.logger.info("="*70)
            
        except Exception as e:
            self.logger.error(f"Pipeline failed: {str(e)}", exc_info=True)
            raise
    
    def collect_data(self) -> List[VulnerabilityReport]:
        """Collect data from all configured sources"""
        
        all_reports = []
        config = self.config.get('data_collection', {})
        
        # HackerOne
        if config.get('collect_hackerone', True):
            self.logger.info("Collecting from HackerOne...")
            try:
                h1_collector = HackerOneCollector(
                    api_token=config.get('hackerone_token')
                )
                h1_reports = h1_collector.collect(
                    limit=config.get('hackerone_limit', 5000),
                    use_cache=True
                )
                all_reports.extend(h1_reports)
                self.logger.info(f"  → HackerOne: {len(h1_reports)} reports")
            except Exception as e:
                self.logger.error(f"  ✗ HackerOne collection failed: {e}")
        
        # Bugcrowd
        if config.get('collect_bugcrowd', True):
            self.logger.info("Collecting from Bugcrowd...")
            try:
                bc_collector = BugcrowdCollector(
                    api_token=config.get('bugcrowd_token')
                )
                bc_reports = bc_collector.collect(
                    limit=config.get('bugcrowd_limit', 2000),
                    use_cache=True
                )
                all_reports.extend(bc_reports)
                self.logger.info(f"  → Bugcrowd: {len(bc_reports)} reports")
            except Exception as e:
                self.logger.error(f"  ✗ Bugcrowd collection failed: {e}")
        
        # CVE/NVD
        if config.get('collect_cve', True):
            self.logger.info("Collecting from NVD...")
            try:
                cve_collector = CVECollector(
                    api_key=config.get('nvd_api_key')
                )
                
                # Date range
                start_date_str = config.get('cve_start_date', '2020-01-01')
                start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
                end_date = datetime.now()
                
                cve_reports = cve_collector.collect(
                    start_date=start_date,
                    end_date=end_date,
                    keywords=['web', 'application', 'api'],
                    limit=config.get('cve_limit', 3000),
                    use_cache=True
                )
                all_reports.extend(cve_reports)
                self.logger.info(f"  → NVD: {len(cve_reports)} reports")
            except Exception as e:
                self.logger.error(f"  ✗ NVD collection failed: {e}")
        
        self.logger.info(f"\nTotal collected: {len(all_reports)} reports")
        
        return all_reports
    
    def preprocess_data(self, reports: List[VulnerabilityReport]) -> List[VulnerabilityReport]:
        """Clean and preprocess data"""
        
        config = self.config.get('preprocessing', {})
        
        # Normalize
        self.logger.info("Normalizing data...")
        normalizer = DataNormalizer()
        normalized = normalizer.normalize(reports)
        self.logger.info(f"  → Normalized: {len(normalized)} reports")
        
        # Deduplicate
        if config.get('remove_duplicates', True):
            self.logger.info("Removing duplicates...")
            deduplicator = Deduplicator()
            deduplicated = deduplicator.deduplicate(normalized)
            self.logger.info(f"  → Deduplicated: {len(deduplicated)} reports")
        else:
            deduplicated = normalized
        
        # Enrich
        self.logger.info("Enriching data...")
        enricher = DataEnricher()
        enriched = enricher.enrich(deduplicated)
        self.logger.info(f"  → Enriched: {len(enriched)} reports")
        
        # Filter low quality
        min_quality = config.get('min_report_quality', 0.0)
        if min_quality > 0:
            self.logger.info(f"Filtering reports with quality < {min_quality}...")
            # Simple quality filter: has description and vulnerability type
            filtered = [
                r for r in enriched 
                if r.description and r.vulnerability_type != 'Other'
            ]
            self.logger.info(f"  → Filtered: {len(filtered)} reports")
        else:
            filtered = enriched
        
        return filtered
    
    def engineer_features(self, reports: List[VulnerabilityReport]) -> pd.DataFrame:
        """Transform reports into features"""
        
        self.feature_engineer = FeatureEngineer()
        features_df = self.feature_engineer.fit_transform(reports)
        
        # Save feature engineer
        self.feature_engineer.save(self.models_dir / 'feature_engineer.pkl')
        
        # Save feature names
        with open(self.models_dir / 'feature_names.json', 'w') as f:
            json.dump(list(features_df.columns), f, indent=2)
        
        return features_df
    
    def split_data(self, features_df: pd.DataFrame, 
                   reports: List[VulnerabilityReport]) -> Tuple:
        """Split data into train/test sets"""
        
        from sklearn.model_selection import train_test_split
        
        config = self.config.get('training', {})
        
        # Extract targets
        y_vuln_type = features_df['vuln_type'].values
        y_severity = features_df['severity'].values
        y_cvss = features_df['cvss_score'].values
        
        # Drop target columns from features
        X = features_df.drop(['vuln_type', 'severity', 'cvss_score'], axis=1, errors='ignore')
        
        # Also drop non-numeric and categorical unencoded columns
        # Keep only numeric and encoded features
        numeric_cols = X.select_dtypes(include=[np.number]).columns
        X = X[numeric_cols]
        
        self.logger.info(f"Features shape: {X.shape}")
        self.logger.info(f"Target distribution:")
        self.logger.info(f"  Vulnerability types: {len(np.unique(y_vuln_type))}")
        self.logger.info(f"  Severity levels: {len(np.unique(y_severity))}")
        
        # Stratified split
        test_size = config.get('test_size', 0.2)
        random_state = config.get('random_state', 42)
        
        X_train, X_test, y_train, y_test, sev_train, sev_test, cvss_train, cvss_test = train_test_split(
            X, y_vuln_type, y_severity, y_cvss,
            test_size=test_size,
            random_state=random_state,
            stratify=y_vuln_type
        )
        
        self.logger.info(f"Train set: {len(X_train)} samples")
        self.logger.info(f"Test set: {len(X_test)} samples")
        
        return X_train, X_test, y_train, y_test, (sev_train, sev_test), (cvss_train, cvss_test)
    
    def train_models(self, X_train, X_test, y_train, y_test, 
                     y_severity: Tuple, y_cvss: Tuple):
        """Train all models"""
        
        config = self.config.get('training', {})
        
        # 1. Vulnerability Type Classifier
        self.logger.info("\n" + "="*70)
        self.logger.info("TRAINING VULNERABILITY CLASSIFIER")
        self.logger.info("="*70)
        
        vuln_predictor = VulnerabilityPredictor(
            random_state=config.get('random_state', 42)
        )
        vuln_predictor.build_models()
        
        vuln_results = vuln_predictor.train(
            pd.DataFrame(X_train, columns=X_train.columns),
            pd.Series(y_train),
            test_size=0.0,  # Already split
            validation_size=config.get('validation_size', 0.1),
            perform_cv=True
        )
        
        self.models['vulnerability_predictor'] = vuln_predictor
        self.metrics['vulnerability_predictor'] = vuln_results
        
        # 2. Severity Predictor
        self.logger.info("\n" + "="*70)
        self.logger.info("TRAINING SEVERITY PREDICTOR")
        self.logger.info("="*70)
        
        severity_predictor = SeverityPredictor(
            random_state=config.get('random_state', 42)
        )
        severity_predictor.build_model()
        
        sev_train, sev_test = y_severity
        cvss_train, cvss_test = y_cvss
        
        severity_results = severity_predictor.train(
            pd.DataFrame(X_train, columns=X_train.columns),
            pd.Series(sev_train),
            y_cvss=pd.Series(cvss_train),
            test_size=0.0,  # Already split
            perform_cv=True
        )
        
        self.models['severity_predictor'] = severity_predictor
        self.metrics['severity_predictor'] = severity_results
        
        # 3. Chain Detector
        self.logger.info("\n" + "="*70)
        self.logger.info("INITIALIZING CHAIN DETECTOR")
        self.logger.info("="*70)
        
        chain_detector = ChainDetector()
        
        # Test chain detection with sample data
        unique_vulns = list(set(y_train))
        detected_chains = chain_detector.detect_chains(unique_vulns)
        
        self.logger.info(f"Chain patterns loaded: {len(chain_detector.chain_patterns)}")
        self.logger.info(f"Chains detectable: {len(detected_chains)}")
        
        self.models['chain_detector'] = chain_detector
    
    def evaluate_models(self, X_test, y_test):
        """Evaluate trained models"""
        
        self.logger.info("Evaluating VulnerabilityPredictor...")
        
        vuln_predictor = self.models['vulnerability_predictor']
        
        # Ensemble evaluation
        eval_results = vuln_predictor.evaluate(
            pd.DataFrame(X_test, columns=X_test.columns),
            pd.Series(y_test),
            method='averaging'
        )
        
        self.logger.info(f"Ensemble Accuracy: {eval_results['accuracy']:.4f}")
        self.logger.info(f"Ensemble F1 Score: {eval_results['f1_score']:.4f}")
        
        # Save evaluation results
        self.metrics['evaluation'] = eval_results
        
        # Feature importance
        if self.config.get('output', {}).get('save_feature_importance', True):
            try:
                feature_importance = vuln_predictor.get_feature_importance(
                    top_n=30,
                    model_name='random_forest'
                )
                
                self.logger.info("\nTop 10 Most Important Features:")
                for idx, row in feature_importance.head(10).iterrows():
                    self.logger.info(f"  {idx+1}. {row['Feature']}: {row['Importance']:.4f}")
                
                # Save to file
                feature_importance.to_csv(
                    self.results_dir / 'feature_importance.csv',
                    index=False
                )
            except Exception as e:
                self.logger.warning(f"Could not extract feature importance: {e}")
    
    def save_models(self):
        """Save all trained models"""
        
        # Save each model
        for name, model in self.models.items():
            model_path = self.models_dir / f"{name}.pkl"
            model.save(str(model_path))
            self.logger.info(f"  ✓ Saved {name}")
        
        # Save metadata
        metadata = {
            'training_date': datetime.now().isoformat(),
            'num_training_samples': len(self.processed_reports),
            'num_features': self.features_df.shape[1] if self.features_df is not None else 0,
            'model_versions': {name: '1.0' for name in self.models.keys()},
            'config': self.config,
            'data_sources': {
                'hackerone': self.config.get('data_collection', {}).get('collect_hackerone', False),
                'bugcrowd': self.config.get('data_collection', {}).get('collect_bugcrowd', False),
                'nvd': self.config.get('data_collection', {}).get('collect_cve', False)
            }
        }
        
        with open(self.models_dir / 'metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)
        
        self.logger.info(f"  ✓ Saved metadata")
    
    def save_metrics(self):
        """Save training metrics"""
        
        # Save full metrics
        metrics_file = self.results_dir / 'training_metrics.json'
        
        # Convert numpy types to native Python types for JSON serialization
        def convert_to_native(obj):
            if isinstance(obj, np.integer):
                return int(obj)
            elif isinstance(obj, np.floating):
                return float(obj)
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, dict):
                return {k: convert_to_native(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_to_native(item) for item in obj]
            return obj
        
        metrics_serializable = convert_to_native(self.metrics)
        
        with open(metrics_file, 'w') as f:
            json.dump(metrics_serializable, f, indent=2)
        
        self.logger.info(f"  ✓ Saved training metrics")
        
        # Save summary report
        self._generate_summary_report()
    
    def _generate_summary_report(self):
        """Generate human-readable summary report"""
        
        report_file = self.results_dir / 'training_summary.txt'
        
        with open(report_file, 'w') as f:
            f.write("="*70 + "\n")
            f.write("BUGPREDICT AI - TRAINING SUMMARY REPORT\n")
            f.write("="*70 + "\n\n")
            
            f.write(f"Training Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Reports Processed: {len(self.processed_reports)}\n")
            f.write(f"Features Generated: {self.features_df.shape[1] if self.features_df is not None else 0}\n\n")
            
            # Vulnerability Classifier Results
            f.write("-"*70 + "\n")
            f.write("VULNERABILITY CLASSIFIER\n")
            f.write("-"*70 + "\n")
            
            if 'vulnerability_predictor' in self.metrics:
                for model_name, results in self.metrics['vulnerability_predictor'].items():
                    if isinstance(results, dict) and 'error' not in results:
                        f.write(f"\n{model_name.upper()}:\n")
                        f.write(f"  Test Accuracy: {results.get('test_accuracy', 0):.4f}\n")
                        f.write(f"  Test F1 Score: {results.get('test_f1', 0):.4f}\n")
                        if results.get('cv_mean'):
                            f.write(f"  CV Mean: {results['cv_mean']:.4f} (+/- {results.get('cv_std', 0):.4f})\n")
            
            # Severity Predictor Results
            f.write("\n" + "-"*70 + "\n")
            f.write("SEVERITY PREDICTOR\n")
            f.write("-"*70 + "\n")
            
            if 'severity_predictor' in self.metrics:
                sev_metrics = self.metrics['severity_predictor']
                if 'severity_classifier' in sev_metrics:
                    f.write(f"\nSeverity Classifier:\n")
                    f.write(f"  Test Accuracy: {sev_metrics['severity_classifier'].get('test_accuracy', 0):.4f}\n")
                    f.write(f"  Test F1 Score: {sev_metrics['severity_classifier'].get('test_f1', 0):.4f}\n")
                
                if 'cvss_regressor' in sev_metrics:
                    f.write(f"\nCVSS Regressor:\n")
                    f.write(f"  Test MAE: {sev_metrics['cvss_regressor'].get('test_mae', 0):.4f}\n")
                    f.write(f"  Test R²: {sev_metrics['cvss_regressor'].get('test_r2', 0):.4f}\n")
            
            # Chain Detector
            f.write("\n" + "-"*70 + "\n")
            f.write("CHAIN DETECTOR\n")
            f.write("-"*70 + "\n")
            f.write(f"\nChain Patterns: {len(self.models['chain_detector'].chain_patterns)}\n")
            
            f.write("\n" + "="*70 + "\n")
            f.write("END OF REPORT\n")
            f.write("="*70 + "\n")
        
        self.logger.info(f"  ✓ Saved summary report")
