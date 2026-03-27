"""
Dependency Vulnerability Scanner — Scans requirements.txt and package.json 
for known vulnerable packages using the OSV (Open Source Vulnerability) API.
Also checks whether declared dependencies are actually used in the source code.
"""
import ast
import json
import os
import re
import ssl
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional, Set
from pathlib import Path


# Standard library module names — we never flag these as undeclared
_STDLIB_MODULES = set(
    __import__("sys").stdlib_module_names
    if hasattr(__import__("sys"), "stdlib_module_names")
    else {
        "os", "sys", "re", "ast", "io", "json", "csv", "math", "time", "uuid",
        "abc", "copy", "enum", "glob", "gzip", "hmac", "html", "http", "hashlib",
        "heapq", "inspect", "itertools", "logging", "pathlib", "pickle", "random",
        "shutil", "signal", "socket", "sqlite3", "string", "struct", "subprocess",
        "tempfile", "threading", "traceback", "typing", "unittest", "urllib",
        "warnings", "weakref", "xml", "zipfile", "zlib", "collections", "contextlib",
        "dataclasses", "datetime", "decimal", "difflib", "email", "functools",
        "importlib", "pkgutil", "platform", "pprint", "queue", "secrets",
        "concurrent", "asyncio", "base64", "binascii", "builtins", "calendar",
        "cmath", "codecs", "configparser", "ctypes", "curses", "dis", "doctest",
        "fractions", "ftplib", "gc", "getopt", "getpass", "grp", "imaplib",
        "keyword", "linecache", "locale", "marshal", "mimetypes", "mmap",
        "multiprocessing", "numbers", "operator", "optparse", "parser", "pdb",
        "pipes", "poplib", "posix", "pstats", "pty", "pwd", "py_compile",
        "pyclbr", "pydoc", "readline", "resource", "rlcompleter", "runpy",
        "sched", "select", "shelve", "smtplib", "sndhdr", "spwd", "ssl",
        "stat", "statistics", "sunau", "symtable", "sysconfig", "syslog",
        "tabnanny", "tarfile", "telnetlib", "termios", "test", "textwrap",
        "token", "tokenize", "tomllib", "trace", "tracemalloc", "tty",
        "turtle", "turtledemo", "types", "unicodedata", "uu", "venv",
        "wave", "wsgiref", "xdrlib", "xmlrpc", "xxlimited", "zipapp",
    }
)

# Map of install name → import name(s) for common packages that differ
_INSTALL_TO_IMPORT: Dict[str, List[str]] = {
    "pillow": ["PIL"],
    "scikit-learn": ["sklearn"],
    "beautifulsoup4": ["bs4"],
    "pyyaml": ["yaml"],
    "python-dotenv": ["dotenv"],
    "opencv-python": ["cv2"],
    "langchain-openai": ["langchain_openai"],
    "langchain-core": ["langchain_core"],
    "langchain-community": ["langchain_community"],
    "sqlalchemy": ["sqlalchemy"],
    "fastapi": ["fastapi"],
    "uvicorn": ["uvicorn"],
    "pydantic": ["pydantic"],
    "httpx": ["httpx"],
    "requests": ["requests"],
    "flask": ["flask"],
    "django": ["django"],
    "numpy": ["numpy", "np"],
    "pandas": ["pandas", "pd"],
    "matplotlib": ["matplotlib"],
    "pytest": ["pytest"],
    "celery": ["celery"],
    "redis": ["redis"],
    "boto3": ["boto3"],
    "botocore": ["botocore"],
    "cryptography": ["cryptography"],
    "paramiko": ["paramiko"],
    "aiohttp": ["aiohttp"],
    "starlette": ["starlette"],
    "alembic": ["alembic"],
    "psycopg2": ["psycopg2"],
    "psycopg2-binary": ["psycopg2"],
    "pymysql": ["pymysql"],
    "motor": ["motor"],
    "pymongo": ["pymongo"],
    "python-jose": ["jose"],
    "passlib": ["passlib"],
    "python-multipart": ["multipart"],
    "email-validator": ["email_validator"],
    "jinja2": ["jinja2"],
    "markupsafe": ["markupsafe"],
    "click": ["click"],
    "typer": ["typer"],
    "rich": ["rich"],
    "loguru": ["loguru"],
    "arrow": ["arrow"],
    "pendulum": ["pendulum"],
    "toml": ["toml"],
    "tomli": ["tomli"],
    "attrs": ["attr", "attrs"],
    "cattrs": ["cattr"],
    "marshmallow": ["marshmallow"],
    "cerberus": ["cerberus"],
    "voluptuous": ["voluptuous"],
    "tqdm": ["tqdm"],
    "tabulate": ["tabulate"],
    "colorama": ["colorama"],
    "termcolor": ["termcolor"],
    "six": ["six"],
    "more-itertools": ["more_itertools"],
    "toolz": ["toolz"],
    "cytoolz": ["cytoolz"],
    "wrapt": ["wrapt"],
    "deprecated": ["deprecated"],
    "packaging": ["packaging"],
    "setuptools": ["setuptools", "pkg_resources"],
    "wheel": ["wheel"],
    "pip": ["pip"],
}


OSV_API_URL = "https://api.osv.dev/v1/query"


class DependencyScanner:
    """Scans dependency manifest files for known vulnerabilities."""

    def check_requirements_usage(self, project_path: str) -> List[Dict[str, Any]]:
        """
        Cross-check requirements.txt against actual imports in .py files.

        Returns issues for:
        - DEP002: Package declared in requirements.txt but never imported
        - DEP003: Package imported in source but not declared in requirements.txt
        """
        project = Path(project_path)
        req_file = project / "requirements.txt"

        if not req_file.exists():
            return []

        declared = self._parse_requirements_txt(req_file.read_text())
        if not declared:
            return []

        third_party_imports = self._collect_third_party_imports(project)
        declared_import_names = self._resolve_declared_import_names(declared)

        return (
            self._find_unused_dependencies(declared, third_party_imports)
            + self._find_undeclared_dependencies(third_party_imports, declared_import_names)
        )

    def _collect_third_party_imports(self, project: Path) -> Set[str]:
        """Walk all .py files and return top-level third-party module names."""
        imported: Set[str] = set()
        skip_dirs = {".git", "__pycache__", ".venv", "venv", "env", ".env",
                     ".tox", ".pytest_cache", "dist", "build", ".eggs"}

        for root, dirs, files in os.walk(project):
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                self._extract_imports_from_file(Path(root) / fname, imported)

        return imported - _STDLIB_MODULES

    def _extract_imports_from_file(self, fpath: Path, imported: Set[str]) -> None:
        """Parse a single .py file and add its top-level imports to the set."""
        try:
            source = fpath.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imported.add(alias.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module.split(".")[0])
        except Exception:
            pass

    def _resolve_declared_import_names(self, declared: List[Dict[str, str]]) -> Set[str]:
        """Build the set of all possible import names from declared packages."""
        names: Set[str] = set()
        for dep in declared:
            install_name = dep["name"].lower()
            for imp in _INSTALL_TO_IMPORT.get(
                install_name, [install_name, install_name.replace("-", "_")]
            ):
                names.add(imp)
        return names

    def _find_unused_dependencies(
        self, declared: List[Dict[str, str]], third_party_imports: Set[str]
    ) -> List[Dict[str, Any]]:
        """Return DEP002 issues for packages declared but never imported."""
        results = []
        for dep in declared:
            install_name = dep["name"].lower()
            possible = _INSTALL_TO_IMPORT.get(
                install_name, [install_name, install_name.replace("-", "_")]
            )
            if not any(imp in third_party_imports for imp in possible):
                results.append({
                    "file": "requirements.txt",
                    "package": dep["name"],
                    "version": dep["version"],
                    "rule_id": "DEP002",
                    "severity": "MINOR",
                    "summary": f"'{dep['name']}' is declared in requirements.txt but never imported in any .py file.",
                    "suggestion": f"Remove '{dep['name']}' from requirements.txt if it is not needed, or verify it is used as a runtime plugin/entry-point.",
                })
        return results

    def _find_undeclared_dependencies(
        self, third_party_imports: Set[str], declared_import_names: Set[str]
    ) -> List[Dict[str, Any]]:
        """Return DEP003 issues for packages imported but not declared."""
        return [
            {
                "file": "requirements.txt",
                "package": mod,
                "version": "",
                "rule_id": "DEP003",
                "severity": "MAJOR",
                "summary": f"'{mod}' is imported in source code but not declared in requirements.txt.",
                "suggestion": f"Add '{mod}' to requirements.txt to ensure reproducible installs.",
            }
            for mod in sorted(third_party_imports)
            if mod not in declared_import_names
        ]

    def scan_project(self, project_path: str) -> List[Dict[str, Any]]:
        """Scan a project directory for dependency vulnerabilities."""
        results = []
        project = Path(project_path)

        # Python dependencies
        req_file = project / "requirements.txt"
        if req_file.exists():
            deps = self._parse_requirements_txt(req_file.read_text())
            for dep in deps:
                vulns = self._query_osv(dep["name"], dep["version"], "PyPI")
                for v in vulns:
                    results.append({
                        "file": str(req_file),
                        "package": dep["name"],
                        "version": dep["version"],
                        "vulnerability_id": v.get("id", "UNKNOWN"),
                        "summary": v.get("summary", "No summary available"),
                        "severity": self._estimate_severity(v),
                        "details": v.get("details", ""),
                        "references": [ref.get("url", "") for ref in v.get("references", [])[:3]],
                    })

        # JavaScript dependencies
        pkg_json = project / "package.json"
        if pkg_json.exists():
            deps = self._parse_package_json(pkg_json.read_text())
            for dep in deps:
                vulns = self._query_osv(dep["name"], dep["version"], "npm")
                for v in vulns:
                    results.append({
                        "file": str(pkg_json),
                        "package": dep["name"],
                        "version": dep["version"],
                        "vulnerability_id": v.get("id", "UNKNOWN"),
                        "summary": v.get("summary", "No summary available"),
                        "severity": self._estimate_severity(v),
                        "details": v.get("details", ""),
                        "references": [ref.get("url", "") for ref in v.get("references", [])[:3]],
                    })

        return results

    def _parse_requirements_txt(self, content: str) -> List[Dict[str, str]]:
        """Parse a requirements.txt file into a list of {name, version}."""
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            # Match: package==version, package>=version, package~=version
            match = re.match(r'^([a-zA-Z0-9_.-]+)\s*[=~><]+\s*([0-9][^\s;#]*)', line)
            if match:
                deps.append({"name": match.group(1), "version": match.group(2)})
            else:
                # Package without version
                match = re.match(r'^([a-zA-Z0-9_.-]+)', line)
                if match:
                    deps.append({"name": match.group(1), "version": ""})
        return deps

    def _parse_package_json(self, content: str) -> List[Dict[str, str]]:
        """Parse a package.json file into a list of {name, version}."""
        deps = []
        try:
            pkg = json.loads(content)
            for section in ["dependencies", "devDependencies"]:
                for name, version in pkg.get(section, {}).items():
                    # Strip version prefixes like ^, ~, >=
                    clean_version = re.sub(r'^[^0-9]*', '', version)
                    deps.append({"name": name, "version": clean_version})
        except json.JSONDecodeError:
            pass
        return deps

    def _query_osv(self, package_name: str, version: str, ecosystem: str) -> List[Dict]:
        """Query the OSV API for vulnerabilities affecting a specific package version."""
        if not version:
            return []

        payload = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem,
            },
            "version": version,
        }

        try:
            req = urllib.request.Request(
                OSV_API_URL,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                result = json.loads(response.read().decode())
                return result.get("vulns", [])
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError) as e:
            print(f"[DependencyScanner] Warning: Failed to query OSV for {package_name}=={version}: {e}")
            return []

    def _estimate_severity(self, vuln: Dict) -> str:
        """Estimate severity from OSV vulnerability data."""
        # Check CVSS scores in severity field
        severities = vuln.get("severity", [])
        for sev in severities:
            score_str = sev.get("score", "")
            # Try to extract CVSS score
            try:
                # CVSS vector string contains score info
                if "CVSS" in sev.get("type", ""):
                    # Parse vector for score if available
                    pass
            except Exception:
                pass

        # Fallback: check aliases for CVE severity indicators
        details = vuln.get("details", "").lower()

        if any(word in details for word in ["critical", "remote code execution", "rce"]):
            return "CRITICAL"
        elif any(word in details for word in ["high", "injection", "overflow"]):
            return "MAJOR"
        elif any(word in details for word in ["medium", "moderate", "xss"]):
            return "MINOR"
        else:
            return "INFO"
