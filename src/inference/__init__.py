"""Inference and prediction for BugPredict AI"""

from .predictor import ThreatPredictor
from .template_generator import NucleiTemplateGenerator

__all__ = [
    'ThreatPredictor',
    'NucleiTemplateGenerator'
]
```

---

## 📁 **Complete Project Structure with `__init__.py`**
```
bugpredict-ai/
├── src/
│   ├── __init__.py                    ✅ NEW
│   ├── collectors/
│   │   ├── __init__.py                ✅ NEW/UPDATED
│   │   ├── data_sources.py
│   │   ├── enhanced_extractor.py
│   │   ├── csv_importer.py            ✅ NEW
│   │   └── json_importer.py           ✅ NEW
│   ├── preprocessing/
│   │   └── __init__.py                ✅ EXISTS
│   ├── features/
│   │   ├── __init__.py                ✅ NEW
│   │   └── feature_engineer.py
│   ├── models/
│   │   ├── __init__.py                ✅ NEW
│   │   ├── vulnerability_classifier.py
│   │   ├── severity_predictor.py
│   │   └── chain_detector.py
│   ├── training/
│   │   ├── __init__.py                ✅ NEW
│   │   ├── pipeline.py
│   │   └── mock_data_generator.py
│   └── inference/
│       ├── __init__.py                ✅ NEW
│       ├── predictor.py
│       └── template_generator.py
├── scripts/
│   ├── train_with_mock_data.py
│   ├── train_from_csv.py              ✅ NEW
│   ├── train_from_json.py             ✅ NEW
│   └── generate_nuclei_templates.py
├── examples/
│   ├── sample_vulnerabilities.csv     ✅ NEW
│   └── sample_vulnerabilities.json    ✅ NEW
└── requirements.txt
