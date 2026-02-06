# 🗄️ Database Guide

Complete guide for setting up and using databases with BugPredict AI.

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Supported Databases](#supported-databases)
3. [SQLite Setup](#sqlite-setup)
4. [PostgreSQL Setup](#postgresql-setup)
5. [MySQL Setup](#mysql-setup)
6. [SQL Server Setup](#sql-server-setup)
7. [Database Schema](#database-schema)
8. [Connection Strings](#connection-strings)
9. [Common Operations](#common-operations)
10. [Troubleshooting](#troubleshooting)

---

## 🎯 Overview

BugPredict AI supports multiple SQL databases for storing and training on vulnerability data. All databases use the same interface through SQLAlchemy, making it easy to switch between different database systems.

**Supported Operations:**
- Import vulnerability reports from any SQL database
- Train ML models directly from database tables
- Filter and query data using SQL WHERE clauses
- Limit training data for faster iterations
- View table schemas and structures

---

## 🗄️ Supported Databases

| Database | Difficulty | Server Required | Best For |
|----------|-----------|-----------------|----------|
| **SQLite** | ⭐ Easy | No | Testing, development, single-user |
| **PostgreSQL** | ⭐⭐ Medium | Yes | Production, multi-user, large datasets |
| **MySQL** | ⭐⭐ Medium | Yes | Web applications, shared hosting |
| **SQL Server** | ⭐⭐⭐ Advanced | Yes | Enterprise, Windows environments |

**Recommendation for beginners:** Start with **SQLite** (no server setup required)

---

## 💾 SQLite Setup

### Why SQLite?
- ✅ No server installation required
- ✅ File-based (portable database)
- ✅ Perfect for testing and development
- ✅ Built into Python (no additional packages)
- ✅ Great for datasets under 1 million records

### Installation

**No installation needed!** SQLite support is built into Python.

### Create Database

#### Option 1: Using Mock Data Generator (Recommended)
```bash
# Create database with 100 vulnerability reports
python scripts/create_mock_database.py --reports 100

# Create larger database
python scripts/create_mock_database.py --reports 1000 --output data/large_vulns.db
```

#### Option 2: Manual Database Creation
```python
import sqlite3

# Create connection
conn = sqlite3.connect('data/my_vulns.db')
cursor = conn.cursor()

# Create table
cursor.execute('''
    CREATE TABLE vulnerability_reports (
        report_id TEXT PRIMARY KEY,
        target_domain TEXT NOT NULL,
        target_company TEXT NOT NULL,
        vulnerability_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        cvss_score REAL NOT NULL,
        tech_stack TEXT,
        description TEXT,
        endpoint TEXT,
        http_method TEXT,
        bounty_amount REAL
    )
''')

conn.commit()
conn.close()
```

### Connection String
```
sqlite:///data/your_database.db
```

**Examples:**
```bash
# Relative path
sqlite:///data/vulns.db

# Absolute path (Windows)
sqlite:///C:/Users/Owner/Desktop/BugPredict-AI/data/vulns.db

# Absolute path (Linux/Mac)
sqlite:////home/user/BugPredict-AI/data/vulns.db
```

### Usage
```bash
# Validate connection
python scripts/train_from_database.py --db "sqlite:///data/vulns.db" --validate-only

# List tables
python scripts/train_from_database.py --db "sqlite:///data/vulns.db" --list-tables

# View schema
python scripts/train_from_database.py --db "sqlite:///data/vulns.db" --schema vulnerability_reports

# Train models
python scripts/train_from_database.py --db "sqlite:///data/vulns.db" --table vulnerability_reports
```

---

## 🐘 PostgreSQL Setup

### Why PostgreSQL?
- ✅ Production-grade database
- ✅ Excellent for large datasets (millions of records)
- ✅ Strong data integrity
- ✅ Advanced querying capabilities
- ✅ Multi-user support

### Installation

#### Windows
1. Download from [postgresql.org](https://www.postgresql.org/download/windows/)
2. Run installer
3. Remember the password you set for `postgres` user
4. Default port: 5432

#### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib -y
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

#### macOS
```bash
brew install postgresql
brew services start postgresql
```

### Python Package
```bash
pip install psycopg2-binary
```

### Create Database
```bash
# Switch to postgres user (Linux)
sudo -u postgres psql

# Or connect as postgres (Windows/Mac)
psql -U postgres
```
```sql
-- Create database
CREATE DATABASE vulndb;

-- Create user
CREATE USER vulnuser WITH PASSWORD 'securepassword123';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE vulndb TO vulnuser;

-- Exit
\q
```

### Create Table
```bash
psql -U vulnuser -d vulndb
```
```sql
CREATE TABLE vulnerability_reports (
    report_id TEXT PRIMARY KEY,
    target_domain TEXT NOT NULL,
    target_company TEXT NOT NULL,
    vulnerability_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss_score REAL NOT NULL,
    tech_stack TEXT,
    description TEXT,
    endpoint TEXT,
    http_method TEXT,
    bounty_amount REAL,
    auth_required BOOLEAN,
    complexity TEXT,
    reported_date DATE,
    researcher_reputation INTEGER
);
```

### Connection String
```
postgresql://username:password@host:port/database
```

**Examples:**
```bash
# Local database
postgresql://vulnuser:securepassword123@localhost:5432/vulndb

# Remote database
postgresql://vulnuser:securepassword123@192.168.1.100:5432/vulndb

# With special characters in password (URL encode them)
postgresql://vulnuser:p%40ssw0rd@localhost:5432/vulndb
```

### Usage
```bash
# Validate connection
python scripts/train_from_database.py \
  --db "postgresql://vulnuser:securepassword123@localhost:5432/vulndb" \
  --validate-only

# Train models
python scripts/train_from_database.py \
  --db "postgresql://vulnuser:securepassword123@localhost:5432/vulndb" \
  --table vulnerability_reports
```

---

## 🐬 MySQL Setup

### Why MySQL?
- ✅ Widely used and well-documented
- ✅ Great for web applications
- ✅ Good performance for medium-sized datasets
- ✅ Available on most shared hosting

### Installation

#### Windows
1. Download from [mysql.com](https://dev.mysql.com/downloads/installer/)
2. Run installer
3. Choose "Developer Default"
4. Set root password
5. Default port: 3306

#### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install mysql-server -y
sudo systemctl start mysql
sudo systemctl enable mysql
sudo mysql_secure_installation
```

#### macOS
```bash
brew install mysql
brew services start mysql
```

### Python Package
```bash
pip install pymysql
```

### Create Database
```bash
# Login to MySQL
mysql -u root -p
```
```sql
-- Create database
CREATE DATABASE vulndb;

-- Create user
CREATE USER 'vulnuser'@'localhost' IDENTIFIED BY 'securepassword123';

-- Grant privileges
GRANT ALL PRIVILEGES ON vulndb.* TO 'vulnuser'@'localhost';
FLUSH PRIVILEGES;

-- Exit
EXIT;
```

### Create Table
```bash
mysql -u vulnuser -p vulndb
```
```sql
CREATE TABLE vulnerability_reports (
    report_id VARCHAR(255) PRIMARY KEY,
    target_domain VARCHAR(255) NOT NULL,
    target_company VARCHAR(255) NOT NULL,
    vulnerability_type VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    cvss_score FLOAT NOT NULL,
    tech_stack TEXT,
    description TEXT,
    endpoint VARCHAR(500),
    http_method VARCHAR(10),
    bounty_amount FLOAT,
    auth_required BOOLEAN,
    complexity VARCHAR(50),
    reported_date DATE,
    researcher_reputation INT
);
```

### Connection String
```
mysql://username:password@host:port/database
```

**Examples:**
```bash
# Local database
mysql://vulnuser:securepassword123@localhost:3306/vulndb

# Remote database
mysql://vulnuser:securepassword123@192.168.1.100:3306/vulndb

# Default port (3306) can be omitted
mysql://vulnuser:securepassword123@localhost/vulndb
```

### Usage
```bash
# Validate connection
python scripts/train_from_database.py \
  --db "mysql://vulnuser:securepassword123@localhost:3306/vulndb" \
  --validate-only

# Train models
python scripts/train_from_database.py \
  --db "mysql://vulnuser:securepassword123@localhost:3306/vulndb" \
  --table vulnerability_reports
```

---

## 🪟 SQL Server Setup

### Why SQL Server?
- ✅ Enterprise-grade features
- ✅ Excellent Windows integration
- ✅ Advanced security features
- ✅ Good for large organizations

### Installation

#### Windows
1. Download [SQL Server Express](https://www.microsoft.com/en-us/sql-server/sql-server-downloads)
2. Download [SQL Server Management Studio (SSMS)](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms)
3. Install both
4. Default instance name: `localhost\SQLEXPRESS`

#### Linux
```bash
# Import Microsoft GPG key
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

# Add repository
sudo add-apt-repository "$(wget -qO- https://packages.microsoft.com/config/ubuntu/20.04/mssql-server-2019.list)"

# Install SQL Server
sudo apt-get update
sudo apt-get install -y mssql-server

# Configure
sudo /opt/mssql/bin/mssql-conf setup
```

### Python Package
```bash
pip install pyodbc
```

**Additional Windows requirement:**
- Install [ODBC Driver for SQL Server](https://docs.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server)

### Create Database

Using SSMS or command line:
```sql
-- Create database
CREATE DATABASE vulndb;
GO

-- Create login
CREATE LOGIN vulnuser WITH PASSWORD = 'SecurePassword123!';
GO

-- Create user
USE vulndb;
CREATE USER vulnuser FOR LOGIN vulnuser;
GO

-- Grant privileges
ALTER ROLE db_owner ADD MEMBER vulnuser;
GO
```

### Create Table
```sql
USE vulndb;
GO

CREATE TABLE vulnerability_reports (
    report_id VARCHAR(255) PRIMARY KEY,
    target_domain VARCHAR(255) NOT NULL,
    target_company VARCHAR(255) NOT NULL,
    vulnerability_type VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    cvss_score FLOAT NOT NULL,
    tech_stack TEXT,
    description TEXT,
    endpoint VARCHAR(500),
    http_method VARCHAR(10),
    bounty_amount FLOAT,
    auth_required BIT,
    complexity VARCHAR(50),
    reported_date DATE,
    researcher_reputation INT
);
GO
```

### Connection String
```
mssql+pyodbc://username:password@host/database?driver=ODBC+Driver+17+for+SQL+Server
```

**Examples:**
```bash
# Local SQL Server Express
mssql+pyodbc://vulnuser:SecurePassword123!@localhost\SQLEXPRESS/vulndb?driver=ODBC+Driver+17+for+SQL+Server

# SQL Server with default instance
mssql+pyodbc://vulnuser:SecurePassword123!@localhost/vulndb?driver=ODBC+Driver+17+for+SQL+Server

# Remote SQL Server
mssql+pyodbc://vulnuser:SecurePassword123!@192.168.1.100/vulndb?driver=ODBC+Driver+17+for+SQL+Server
```

### Usage
```bash
# Validate connection
python scripts/train_from_database.py \
  --db "mssql+pyodbc://vulnuser:SecurePassword123!@localhost/vulndb?driver=ODBC+Driver+17+for+SQL+Server" \
  --validate-only

# Train models
python scripts/train_from_database.py \
  --db "mssql+pyodbc://vulnuser:SecurePassword123!@localhost/vulndb?driver=ODBC+Driver+17+for+SQL+Server" \
  --table vulnerability_reports
```

---

## 📊 Database Schema

### Required Columns

These columns are **required** for training models:

| Column Name | Data Type | Description |
|-------------|-----------|-------------|
| `report_id` | TEXT/VARCHAR | Unique identifier for each report |
| `target_domain` | TEXT/VARCHAR | Target domain (e.g., example.com) |
| `target_company` | TEXT/VARCHAR | Company name |
| `vulnerability_type` | TEXT/VARCHAR | Type of vulnerability |
| `severity` | TEXT/VARCHAR | Severity level (critical/high/medium/low) |
| `cvss_score` | REAL/FLOAT | CVSS score (0.0 - 10.0) |

### Optional Columns

These columns enhance model accuracy but are not required:

| Column Name | Data Type | Description |
|-------------|-----------|-------------|
| `tech_stack` | TEXT | Technologies used (comma-separated) |
| `description` | TEXT | Vulnerability description |
| `endpoint` | TEXT/VARCHAR | Affected endpoint |
| `http_method` | TEXT/VARCHAR | HTTP method (GET/POST/etc) |
| `bounty_amount` | REAL/FLOAT | Bounty payout amount |
| `auth_required` | BOOLEAN/BIT | Authentication required |
| `complexity` | TEXT/VARCHAR | Exploit complexity (low/medium/high) |
| `reported_date` | DATE | Date reported |
| `researcher_reputation` | INTEGER | Researcher reputation score |

### Example Schema (All Databases)
```sql
CREATE TABLE vulnerability_reports (
    -- Required fields
    report_id VARCHAR(255) PRIMARY KEY,
    target_domain VARCHAR(255) NOT NULL,
    target_company VARCHAR(255) NOT NULL,
    vulnerability_type VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    cvss_score FLOAT NOT NULL,
    
    -- Optional fields (improves accuracy)
    tech_stack TEXT,
    description TEXT,
    endpoint VARCHAR(500),
    http_method VARCHAR(10),
    bounty_amount FLOAT,
    auth_required BOOLEAN,  -- BIT for SQL Server
    complexity VARCHAR(50),
    reported_date DATE,
    researcher_reputation INTEGER
);
```

---

## 🔗 Connection Strings

### Format Reference
```
database://username:password@host:port/database_name
```

### SQLite
```
sqlite:///relative/path/to/database.db
sqlite:////absolute/path/to/database.db  # Note: 4 slashes for absolute path
```

### PostgreSQL
```
postgresql://username:password@host:port/database
postgresql://username:password@host/database  # Default port 5432
```

### MySQL
```
mysql://username:password@host:port/database
mysql://username:password@host/database  # Default port 3306
```

### SQL Server
```
mssql+pyodbc://username:password@host/database?driver=ODBC+Driver+17+for+SQL+Server
mssql+pyodbc://username:password@host\INSTANCE/database?driver=ODBC+Driver+17+for+SQL+Server
```

### Special Characters in Passwords

If your password contains special characters, URL-encode them:

| Character | URL-Encoded |
|-----------|-------------|
| `@` | `%40` |
| `:` | `%3A` |
| `/` | `%2F` |
| `?` | `%3F` |
| `#` | `%23` |
| `%` | `%25` |

**Example:**
```
# Password: p@ss:word/123
# Encoded: p%40ss%3Aword%2F123

postgresql://user:p%40ss%3Aword%2F123@localhost/vulndb
```

---

## 🛠️ Common Operations

### List All Tables
```bash
python scripts/train_from_database.py --db "CONNECTION_STRING" --list-tables
```

**Example output:**
```
Available tables:
  - vulnerability_reports
  - users
  - programs
```

### View Table Schema
```bash
python scripts/train_from_database.py --db "CONNECTION_STRING" --schema TABLE_NAME
```

**Example output:**
```
Schema for table 'vulnerability_reports':
  report_id                      VARCHAR(255)         NOT NULL
  target_domain                  VARCHAR(255)         NOT NULL
  vulnerability_type             VARCHAR(255)         NOT NULL
  severity                       VARCHAR(50)          NOT NULL
  cvss_score                     FLOAT                NOT NULL
  ...
```

### Import All Data
```bash
python scripts/train_from_database.py --db "CONNECTION_STRING" --table vulnerability_reports
```

### Import with Filters
```bash
# Only high and critical severity
python scripts/train_from_database.py \
  --db "CONNECTION_STRING" \
  --table vulnerability_reports \
  --where "severity='high' OR severity='critical'"

# Only recent reports
python scripts/train_from_database.py \
  --db "CONNECTION_STRING" \
  --table vulnerability_reports \
  --where "reported_date >= '2025-01-01'"

# Only specific vulnerability types
python scripts/train_from_database.py \
  --db "CONNECTION_STRING" \
  --table vulnerability_reports \
  --where "vulnerability_type IN ('SQL Injection', 'XSS', 'RCE')"
```

### Limit Records
```bash
# Import only first 100 records
python scripts/train_from_database.py \
  --db "CONNECTION_STRING" \
  --table vulnerability_reports \
  --limit 100

# Combine limit with filter
python scripts/train_from_database.py \
  --db "CONNECTION_STRING" \
  --table vulnerability_reports \
  --where "severity='critical'" \
  --limit 50
```

---

## 🐛 Troubleshooting

### SQLite Issues

#### Issue: "unable to open database file"

**Solution:**
```bash
# Check if data directory exists
mkdir -p data

# Use absolute path
python scripts/train_from_database.py --db "sqlite:///$(pwd)/data/vulns.db" --validate-only
```

#### Issue: "database is locked"

**Solution:**
- Close all other programs using the database
- Wait a few seconds and try again
- Check if another Python process is accessing the file

---

### PostgreSQL Issues

#### Issue: "FATAL: password authentication failed"

**Solution:**
```bash
# Verify username and password
psql -U vulnuser -d vulndb

# Reset password if needed
sudo -u postgres psql
ALTER USER vulnuser WITH PASSWORD 'newpassword';
\q
```

#### Issue: "could not connect to server"

**Solution:**
```bash
# Check if PostgreSQL is running
sudo systemctl status postgresql  # Linux
brew services list  # macOS

# Start PostgreSQL if stopped
sudo systemctl start postgresql  # Linux
brew services start postgresql  # macOS

# Check port
sudo netstat -tlnp | grep 5432  # Linux
lsof -i :5432  # macOS
```

---

### MySQL Issues

#### Issue: "Access denied for user"

**Solution:**
```bash
# Login as root
mysql -u root -p

# Grant privileges again
GRANT ALL PRIVILEGES ON vulndb.* TO 'vulnuser'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

#### Issue: "Can't connect to MySQL server"

**Solution:**
```bash
# Check if MySQL is running
sudo systemctl status mysql  # Linux
brew services list  # macOS

# Start MySQL
sudo systemctl start mysql  # Linux
brew services start mysql  # macOS
```

---

### SQL Server Issues

#### Issue: "ODBC Driver not found"

**Solution:**
- Download and install [ODBC Driver 17 for SQL Server](https://docs.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server)
- Check installed drivers: `odbcinst -q -d` (Linux)

#### Issue: "Login failed for user"

**Solution:**
```sql
-- In SSMS or sqlcmd
USE vulndb;
ALTER ROLE db_owner ADD MEMBER vulnuser;
GO
```

---

### General Database Issues

#### Issue: "No module named 'psycopg2'" (or pymysql, pyodbc)

**Solution:**
```bash
# PostgreSQL
pip install psycopg2-binary

# MySQL
pip install pymysql

# SQL Server
pip install pyodbc
```

#### Issue: Connection timeout

**Solution:**
- Check firewall settings
- Verify database server is accessible
- Ping the database host: `ping database_host`
- Check if port is open: `telnet database_host port`

---

## 📚 Quick Reference

### Connection String Templates
```bash
# SQLite
sqlite:///data/database.db

# PostgreSQL
postgresql://user:pass@localhost:5432/dbname

# MySQL
mysql://user:pass@localhost:3306/dbname

# SQL Server
mssql+pyodbc://user:pass@localhost/dbname?driver=ODBC+Driver+17+for+SQL+Server
```

### Common Commands
```bash
# Validate connection
python scripts/train_from_database.py --db "CONNECTION" --validate-only

# List tables
python scripts/train_from_database.py --db "CONNECTION" --list-tables

# View schema
python scripts/train_from_database.py --db "CONNECTION" --schema TABLE

# Import and train
python scripts/train_from_database.py --db "CONNECTION" --table TABLE

# With filters
python scripts/train_from_database.py --db "CONNECTION" --table TABLE --where "severity='high'"

# With limit
python scripts/train_from_database.py --db "CONNECTION" --table TABLE --limit 100
```

---

**Database setup complete! Ready to import data and train models.** 🎯
