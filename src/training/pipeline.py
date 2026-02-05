"""Training pipeline for BugPredict AI models"""

import logging
import pickle
from pathlib import Path
from typing import List, Dict, Any, Optional
import pandas as pd
from datetime import datetime

from ..collectors.data_sources import VulnerabilityReport
from ..features.feature_engineer import FeatureEngineer


class TrainingPipeline:
    """Complete training pipeline for vulnerability prediction models"""
    
    def __init__(self, models_dir: str = "data/models"):
        """
        Initialize the training pipeline
        
        Args:
            models_dir: Directory to save trained models
        """
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.feature_engineer = FeatureEngineer()
        
        # Storage for processed data
        self.raw_reports = []
        self.processed_reports = []
        self.feature_data = None
        
        # Models
        self.vulnerability_model = None
        self.severity_model = None
        self.chain_detector = None
        
        # Label encoders
        self.vulnerability_label_encoder = None
        self.severity_label_encoder = None
        
        # Setup logging
        self.logger = self._setup_logger()
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        
        # Console handler
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(logging.INFO)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def load_data(self, data_path: str) -> List[VulnerabilityReport]:
        """
        Loa
