"""
Core configuration for the Code Quality & Security Analysis Platform.
"""
import os
from pathlib import Path

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Database
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'data' / 'codequality.db'}")

# Scan settings
MAX_FILE_SIZE_KB = int(os.getenv("MAX_FILE_SIZE_KB", "500"))
SUPPORTED_EXTENSIONS = {
    "python": [".py"],
    "javascript": [".js", ".jsx", ".ts", ".tsx"],
    "sql": [".sql"],
    "csharp": [".cs"],
}

# Severity levels
class Severity:
    INFO = "INFO"
    MINOR = "MINOR"
    MAJOR = "MAJOR"
    CRITICAL = "CRITICAL"
    BLOCKER = "BLOCKER"

    ALL = [INFO, MINOR, MAJOR, CRITICAL, BLOCKER]
    WEIGHTS = {INFO: 1, MINOR: 2, MAJOR: 5, CRITICAL: 10, BLOCKER: 20}

# Issue categories
class Category:
    SECURITY = "SECURITY"
    CODE_SMELL = "CODE_SMELL"
    PERFORMANCE = "PERFORMANCE"
    COMPLEXITY = "COMPLEXITY"
    MAINTAINABILITY = "MAINTAINABILITY"
    VULNERABILITY = "VULNERABILITY"
    DEPENDENCY = "DEPENDENCY"

# OWASP Top 10 mapping
class OWASP:
    A01_BROKEN_ACCESS_CONTROL = "A01:2021-Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021-Cryptographic Failures"
    A03_INJECTION = "A03:2021-Injection"
    A04_INSECURE_DESIGN = "A04:2021-Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021-Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021-Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021-Identification and Authentication Failures"
    A08_DATA_INTEGRITY_FAILURES = "A08:2021-Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021-Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021-Server-Side Request Forgery"

# API settings
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
