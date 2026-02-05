"""BugPredict AI - Vulnerability Prediction System"""

__version__ = "1.0.0"
__author__ = "BugPredict AI Team"

from . import collectors
from . import preprocessing
from . import features
from . import models
from . import training
from . import inference

__all__ = [
    'collectors',
    'preprocessing',
    'features',
    'models',
    'training',
    'inference'
]
