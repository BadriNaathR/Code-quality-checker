"""
Scanner Engine Orchestrator — Coordinates the full analysis pipeline.

Orchestrates:
    1. File discovery (walk project tree)
    2. Language detection
    3. AST parsing
    4. Rule engine execution
    5. Taint analysis
    6. Metrics calculation
    7. Dependency scanning
    8. Results aggregation and persistence
"""
import os
import time
import json
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from backend.core.config import SUPPORTED_EXTENSIONS, MAX_FILE_SIZE_KB
from backend.parsers.python_parser import PythonParser
from backend.parsers.js_parser import JavaScriptParser
from backend.rule_engine.engine import RuleEngine
from backend.taint_engine.tracker import TaintTracker
from backend.metrics.calculator import MetricsCalculator
from backend.metrics.js_calculator import JSMetricsCalculator
from backend.dependency_scanner.scanner import DependencyScanner


class ScannerEngine:
    """
    Main orchestrator for static analysis scans.
    Manages the lifecycle of scanning a project: file discovery,
    parsing, rule checking, taint analysis, metrics, and dependency scanning.
    """

    def __init__(self):
        self.python_parser = PythonParser()
        self.js_parser = JavaScriptParser()
        self.rule_engine = RuleEngine()
        self.taint_tracker = TaintTracker()
        self.metrics_calculator = MetricsCalculator()
        self.js_metrics_calculator = JSMetricsCalculator()
        self.dependency_scanner = DependencyScanner()

    def scan_project(self, project_path: str, language: Optional[str] = None) -> Dict[str, Any]:
        """
        Run a full analysis on a project directory.

        Args:
            project_path: Path to the project directory.
            language: Optional language filter (e.g., 'python', 'javascript'). 
                      If None, all supported languages are scanned.

        Returns:
            A dict with 'issues', 'metrics', 'dependency_vulnerabilities', and 'summary'.
        """
        start_time = time.time()

        project = Path(project_path)
        if not project.exists() or not project.is_dir():
            return {"error": f"Project path does not exist or is not a directory: {project_path}"}

        # Determine which extensions to scan.
        # 'auto' or unknown language = scan all supported extensions.
        # A specific language = still scan all (rules are per-file language detected),
        # but record the chosen language for display purposes.
        extensions = set()
        for exts in SUPPORTED_EXTENSIONS.values():
            extensions.update(exts)

        # Discover files
        files = self._discover_files(project, extensions)
        all_issues = []
        all_metrics = []
        files_content: Dict[str, str] = {}
        total_lines = 0
        files_scanned = 0

        for filepath in files:
            try:
                source_code = filepath.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                print(f"[ScannerEngine] Error reading {filepath}: {e}")
                continue

            files_content[str(filepath)] = source_code
            total_lines += len(source_code.splitlines())
            files_scanned += 1

            # Determine file language
            file_lang = self._detect_language(filepath)
            resolved = filepath.resolve()
            project_resolved = project.resolve()
            if not str(resolved).startswith(str(project_resolved) + os.sep):
                print(f"[ScannerEngine] Skipping path outside project root: {filepath}")
                continue
            rel_path = str(resolved.relative_to(project_resolved))

            if file_lang == "python":
                # Parse AST
                tree = self.python_parser.parse(source_code, rel_path)
                if tree:
                    # Run rules
                    issues = self.rule_engine.run(tree, source_code, rel_path, language="python")
                    all_issues.extend(issues)

                    # Taint analysis
                    taint_issues = self.taint_tracker.analyze(tree, source_code, rel_path)
                    for ti in taint_issues:
                        all_issues.append({
                            "file": rel_path,
                            "line": ti.line,
                            "column": ti.column,
                            "end_line": ti.end_line,
                            "rule_id": "TAINT001",
                            "rule_name": "Taint Flow Detected",
                            "severity": "CRITICAL",
                            "category": "SECURITY",
                            "message": ti.message,
                            "suggestion": ti.suggestion,
                            "owasp_category": "A03:2021-Injection",
                            "code_snippet": ti.code_snippet,
                        })

                    # Metrics
                    metrics = self.metrics_calculator.calculate_all(source_code, rel_path)
                    all_metrics.extend(metrics)

            elif file_lang == "javascript":
                # JS analysis
                js_tree = self.js_parser.parse(source_code, rel_path)
                issues = self.rule_engine.run(js_tree, source_code, rel_path, language="javascript")
                all_issues.extend(issues)

                # JS Metrics
                js_metrics = self.js_metrics_calculator.calculate_all(source_code, rel_path)
                all_metrics.extend(js_metrics)

            elif file_lang in ("sql", "csharp"):
                # Regex-based analysis — no AST parser needed
                issues = self.rule_engine.run(None, source_code, rel_path, language=file_lang)
                all_issues.extend(issues)

        # Dependency scanning
        dep_vulns = self.dependency_scanner.scan_project(project_path)

        # Requirements usage check (unused / undeclared packages)
        dep_vulns.extend(self.dependency_scanner.check_requirements_usage(project_path))

        # Duplication detection
        duplicates = self.metrics_calculator.detect_duplicates(files_content)

        # Summary
        duration = round(time.time() - start_time, 2)
        severity_counts = {"INFO": 0, "MINOR": 0, "MAJOR": 0, "CRITICAL": 0, "BLOCKER": 0}
        for issue in all_issues:
            sev = issue.get("severity", "INFO")
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Language breakdown (actual detected languages, not the user-selected hint)
        lang_counts: Dict[str, int] = {}
        for issue in all_issues:
            f = issue.get("file", "")
            lang = self._detect_language(Path(f)) if f else "unknown"
            lang_counts[lang] = lang_counts.get(lang, 0) + 1

        summary = {
            "files_scanned": files_scanned,
            "lines_scanned": total_lines,
            "total_issues": len(all_issues),
            "severity_counts": severity_counts,
            "dependency_vulnerabilities": len(dep_vulns),
            "duplicated_blocks": len(duplicates),
            "scan_duration_seconds": duration,
            "language_breakdown": lang_counts,
        }

        return {
            "issues": all_issues,
            "metrics": all_metrics,
            "dependency_vulnerabilities": dep_vulns,
            "duplicates": duplicates,
            "summary": summary,
        }

    def _discover_files(self, project: Path, extensions: set) -> List[Path]:
        """Walk project tree and discover source files matching extensions."""
        files = []
        skip_dirs = {
            '.git', '__pycache__', 'node_modules', '.venv', 'venv',
            'env', '.env', '.tox', '.pytest_cache', '.mypy_cache',
            'dist', 'build', '.eggs',
        }
        for root, dirs, filenames in os.walk(project):
            # Skip hidden and common non-source directories
            dirs[:] = [
                d for d in dirs
                if d not in skip_dirs
                and not d.startswith('.')
                and not d.endswith('.egg-info')
            ]
            for fname in filenames:
                fpath = Path(root) / fname
                if fpath.suffix in extensions:
                    try:
                        resolved = fpath.resolve()
                        if not resolved.is_relative_to(project.resolve()):
                            continue
                        size_kb = resolved.stat().st_size / 1024
                        if size_kb <= MAX_FILE_SIZE_KB:
                            files.append(resolved)
                    except OSError:
                        continue
        return files

    def _detect_language(self, filepath: Path) -> str:
        """Detect the programming language from file extension."""
        ext = filepath.suffix
        for lang, exts in SUPPORTED_EXTENSIONS.items():
            if ext in exts:
                return lang
        return "unknown"
