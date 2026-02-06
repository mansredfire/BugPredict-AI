# 📦 Installation Guide

Complete installation and uninstallation instructions for BugPredict AI.

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
   - [Windows](#windows-installation)
   - [Linux](#linux-installation)
   - [macOS](#macos-installation)
3. [Verification](#verification)
4. [Post-Installation Setup](#post-installation-setup)
5. [Updating](#updating)
6. [Uninstallation](#uninstallation)
7. [Troubleshooting](#troubleshooting)

---

## 📋 Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **Python** | 3.10+ | 3.11+ |
| **pip** | Latest version | Latest version |
| **RAM** | 4GB | 8GB |
| **Disk Space** | 2GB free | 5GB free |
| **OS** | Windows 10+, Ubuntu 20.04+, macOS 10.15+ | Latest versions |

### Check Python Version
```bash
python --version
# Should display: Python 3.10.x or higher
```

**If Python is not installed or version is too old:**

- **Windows**: Download from [python.org](https://www.python.org/downloads/)
- **Linux**: `sudo apt install python3.10 python3-pip`
- **macOS**: `brew install python@3.10`

### Check pip Version
```bash
pip --version
# or
python -m pip --version
```

**Update pip if needed:**
```bash
python -m pip install --upgrade pip
```

---

## 🚀 Installation

### Windows Installation

#### Step 1: Download Project

**Option A: Download ZIP (Recommended for beginners)**
1. Go to GitHub repository
2. Click **Code** → **Download ZIP**
3. Extract to `Desktop` or your preferred location

**Option B: Clone with Git**
```powershell
git clone https://github.com/yourusername/BugPredict-AI.git
cd BugPredict-AI
```

#### Step 2: Open PowerShell in Project Directory
```powershell
# Navigate to project folder
cd ~\Desktop\BugPredict-AI-main  # If you downloaded ZIP
# OR
cd ~\Desktop\BugPredict-AI  # If you cloned with Git
```

#### Step 3: Create Virtual Environment
```powershell
python -m venv venv
```

#### Step 4: Activate Virtual Environment
```powershell
.\venv\Scripts\Activate.ps1
```

**If you get an execution policy error:**
```powershell
# Run PowerShell as Administrator and execute:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Then try activating again:
.\venv\Scripts\Activate.ps1
```

**Your prompt should now show `(venv)` at the beginning.**

#### Step 5: Install Dependencies
```powershell
pip install -r requirements.txt
```

**This installs:**
- pandas (data processing)
- scikit-learn (ML models)
- sqlalchemy (database support)
- pyyaml (template generation)

#### Step 6: Verify Installation
```powershell
python -c "from src.collectors import CSVImporter; print('✓ Installation successful!')"
```

**Expected output:**
```
✓ Installation successful!
```

---

### Linux Installation

#### Step 1: Install Prerequisites (Ubuntu/Debian)
```bash
# Update package list
sudo apt update

# Install Python and pip
sudo apt install python3.10 python3-pip python3-venv git -y
```

#### Step 2: Clone Repository
```bash
git clone https://github.com/yourusername/BugPredict-AI.git
cd BugPredict-AI
```

#### Step 3: Create Virtual Environment
```bash
python3 -m venv venv
```

#### Step 4: Activate Virtual Environment
```bash
source venv/bin/activate
```

**Your prompt should now show `(venv)` at the beginning.**

#### Step 5: Install Dependencies
```bash
pip install -r requirements.txt
```

#### Step 6: Verify Installation
```bash
python -c "from src.collectors import CSVImporter; print('✓ Installation successful!')"
```

**Expected output:**
```
✓ Installation successful!
```

---

### macOS Installation

#### Step 1: Install Homebrew (if not installed)
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### Step 2: Install Python
```bash
brew install python@3.10
```

#### Step 3: Clone Repository
```bash
git clone https://github.com/yourusername/BugPredict-AI.git
cd BugPredict-AI
```

#### Step 4: Create Virtual Environment
```bash
python3 -m venv venv
```

#### Step 5: Activate Virtual Environment
```bash
source venv/bin/activate
```

**Your prompt should now show `(venv)` at the beginning.**

#### Step 6: Install Dependencies
```bash
pip install -r requirements.txt
```

#### Step 7: Verify Installation
```bash
python -c "from src.collectors import CSVImporter; print('✓ Installation successful!')"
```

**Expected output:**
```
✓ Installation successful!
```

---

## ✅ Verification

### Test Core Functionality

#### 1. Verify All Imports
```bash
python -c "from src.collectors import CSVImporter, JSONImporter, DatabaseImporter; from src.training.pipeline import TrainingPipeline; print('✓ All imports successful!')"
```

#### 2. List Available Scripts
```bash
# Windows
dir scripts\

# Linux/Mac
ls scripts/
```

**Should show:**
- `create_mock_database.py`
- `train_from_csv.py`
- `train_from_json.py`
- `train_from_database.py`
- `generate_nuclei_templates.py`

#### 3. Test Script Execution
```bash
python scripts/create_mock_database.py --help
```

**Should display help message without errors.**

#### 4. Check Python Packages
```bash
pip list
```

**Should include:**
- pandas
- scikit-learn
- sqlalchemy
- pyyaml
- numpy

---

## 🔧 Post-Installation Setup

### Create Required Directories
```bash
# Windows PowerShell
New-Item -ItemType Directory -Path data -Force
New-Item -ItemType Directory -Path data\models -Force
New-Item -ItemType Directory -Path nuclei-templates\custom -Force

# Linux/Mac
mkdir -p data/models
mkdir -p nuclei-templates/custom
```

### Generate Test Data (Optional)
```bash
# Create mock database with 100 vulnerability reports
python scripts/create_mock_database.py --reports 100
```

**Expected output:**
```
======================================================================
Mock Vulnerability Database Generator
======================================================================

Creating 100 mock vulnerability reports...

✓ Created database: data/mock_vulns.db
Total reports: 100
...
```

### Test Database Connection
```bash
python scripts/train_from_database.py --db "sqlite:///data/mock_vulns.db" --validate-only
```

**Expected output:**
```
======================================================================
BugPredict AI - Database Training
======================================================================

Validating database connection...
✓ Connected to sqlite database

✓ Validation complete (--validate-only mode)
```

---

## 🔄 Updating

### Update to Latest Version

#### Step 1: Backup Your Data (Optional)
```bash
# Windows
Copy-Item -Path data -Destination data_backup -Recurse

# Linux/Mac
cp -r data data_backup
```

#### Step 2: Pull Latest Changes

**If installed via Git:**
```bash
git pull origin main
```

**If downloaded ZIP:**
1. Download new ZIP from GitHub
2. Extract to a new location
3. Copy your `data/` folder from old installation to new installation

#### Step 3: Update Dependencies
```bash
# Activate virtual environment first
# Windows: .\venv\Scripts\Activate.ps1
# Linux/Mac: source venv/bin/activate

# Update packages
pip install --upgrade -r requirements.txt
```

#### Step 4: Verify Update
```bash
python -c "from src.collectors import CSVImporter; print('✓ Update successful!')"
```

---

## 🗑️ Uninstallation

### Complete Removal

#### Step 1: Deactivate Virtual Environment
```bash
deactivate
```

#### Step 2: Navigate to Parent Directory
```bash
cd ..
```

#### Step 3: Remove Project Directory

**Windows PowerShell:**
```powershell
Remove-Item -Recurse -Force BugPredict-AI
# or BugPredict-AI-main if you downloaded ZIP
```

**Linux/Mac:**
```bash
rm -rf BugPredict-AI
```

### Partial Removal (Keep Data)

If you want to keep your trained models and databases:

**Windows PowerShell:**
```powershell
# Remove only code
Remove-Item -Recurse -Force venv, src, scripts

# Keep these:
# - data/ (trained models, databases)
# - nuclei-templates/ (generated templates)
```

**Linux/Mac:**
```bash
# Remove only code
rm -rf venv/ src/ scripts/

# Keep these:
# - data/ (trained models, databases)
# - nuclei-templates/ (generated templates)
```

---

## 🐛 Troubleshooting

### Common Issues

#### Issue 1: `ModuleNotFoundError: No module named 'src'`

**Cause:** Python can't find the `src` module.

**Solution:**
```bash
# Make sure you're in the project root directory
pwd  # Should show: .../BugPredict-AI

# Add project to Python path
# Windows PowerShell:
$env:PYTHONPATH="$env:PYTHONPATH;$(Get-Location)"

# Linux/Mac:
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Or run scripts from project root:
python scripts/your_script.py
```

---

#### Issue 2: `pip install` fails

**Solution 1: Update pip**
```bash
python -m pip install --upgrade pip
```

**Solution 2: Use --user flag**
```bash
pip install --user -r requirements.txt
```

**Solution 3: Check Python version**
```bash
python --version  # Must be 3.10 or higher
```

---

#### Issue 3: Virtual environment won't activate (Windows)

**Cause:** PowerShell execution policy restriction.

**Solution:**
```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Then activate:
.\venv\Scripts\Activate.ps1
```

---

#### Issue 4: `ImportError: No module named 'pandas'` (or other packages)

**Cause:** Dependencies not installed or virtual environment not activated.

**Solution:**
```bash
# 1. Make sure virtual environment is activated
# You should see (venv) in your prompt

# 2. Reinstall dependencies
pip install -r requirements.txt

# 3. Verify installation
pip list | grep pandas  # Linux/Mac
pip list | findstr pandas  # Windows
```

---

#### Issue 5: Database connection errors

**Cause:** Missing database drivers.

**Solution:**

**For PostgreSQL:**
```bash
pip install psycopg2-binary
```

**For MySQL:**
```bash
pip install pymysql
```

**For SQL Server:**
```bash
pip install pyodbc
```

**For SQLite:** No additional package needed (built-in)

---

#### Issue 6: Permission denied errors (Linux/Mac)

**Cause:** Insufficient file permissions.

**Solution:**
```bash
# Make scripts executable
chmod +x scripts/*.py

# Or use sudo for system-wide installation (not recommended)
sudo pip install -r requirements.txt
```

---

#### Issue 7: SSL Certificate errors

**Cause:** Outdated SSL certificates.

**Solution:**
```bash
pip install --upgrade certifi
```

---

#### Issue 8: Out of memory during training

**Cause:** Insufficient RAM.

**Solution:**
- Train with fewer reports
- Close other applications
- Use `--limit` parameter:
```bash
python scripts/train_from_database.py --db "sqlite:///data/vulns.db" --table reports --limit 500
```

---

### Platform-Specific Tips

#### Windows
- Use **PowerShell** (not CMD) for better compatibility
- If SSL errors persist: `pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt`
- Antivirus may flag ML libraries - add exception if needed

#### Linux
- May need build tools: `sudo apt install build-essential python3-dev`
- For PostgreSQL support: `sudo apt install libpq-dev`
- Use `python3` instead of `python` if both Python 2 and 3 are installed

#### macOS
- Use Homebrew for Python installation
- May need Xcode Command Line Tools: `xcode-select --install`
- If OpenSSL errors: `brew install openssl`

---

## 📊 Installation Checklist

Use this checklist to verify successful installation:

- [ ] Python 3.10+ installed and verified
- [ ] pip updated to latest version
- [ ] Project downloaded/cloned to local machine
- [ ] Virtual environment created
- [ ] Virtual environment activated (shows `(venv)` in prompt)
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] Import test passed: `python -c "from src.collectors import CSVImporter; print('✓')"`
- [ ] Required directories created (`data/`, `nuclei-templates/custom/`)
- [ ] Mock database created and tested (optional)
- [ ] Database connection validated (optional)

---

## 🔗 Next Steps

After successful installation:

1. **[Read TRAINING.md](TRAINING.md)** - Learn how to train models
2. **[Read DATABASE.md](DATABASE.md)** - Set up database connections
3. **[Read SCRIPTS.md](SCRIPTS.md)** - Learn all available commands

---

## 💡 Quick Reference

### Activate Virtual Environment
```bash
# Windows
.\venv\Scripts\Activate.ps1

# Linux/Mac
source venv/bin/activate
```

### Deactivate Virtual Environment
```bash
deactivate
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Update Dependencies
```bash
pip install --upgrade -r requirements.txt
```

### Verify Installation
```bash
python -c "from src.collectors import CSVImporter; print('✓')"
```

---

**Installation complete! Ready to train models and generate Nuclei templates.** 🎯
