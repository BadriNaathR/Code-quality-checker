"""
Rule Engine - Discovers, loads, and executes all rules against parsed ASTs.
"""
import importlib
import pkgutil
from typing import List, Dict, Any
from backend.rule_engine.base import BaseRule, RuleIssue


class RuleEngine:
    """
    The pluggable rule engine. 
    Automatically discovers rules from the backend.rules package.
    """

    def __init__(self):
        self.rules: List[BaseRule] = []
        self._discover_rules()

    def _discover_rules(self):
        """Auto-discover all rule modules under backend.rules.*"""
        import backend.rules as rules_package
        self._load_rules_from_package(rules_package)

    def _load_rules_from_package(self, package):
        """Recursively load rules from a package and its sub-packages."""
        for importer, modname, ispkg in pkgutil.walk_packages(
            path=package.__path__,
            prefix=package.__name__ + ".",
        ):
            try:
                module = importlib.import_module(modname)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseRule)
                        and attr is not BaseRule
                    ):
                        rule_instance = attr()
                        self.rules.append(rule_instance)
            except Exception as e:
                print(f"[RuleEngine] Warning: Failed to load rule module {modname}: {e}")

    def run(self, ast_tree, source_code: str, filename: str, language: str = "python") -> List[Dict[str, Any]]:
        """
        Run all applicable rules against the given AST and source code.

        Returns a list of issue dictionaries.
        """
        issues = []
        for rule in self.rules:
            if language not in rule.languages:
                continue
            try:
                rule_issues: List[RuleIssue] = rule.check(ast_tree, source_code, filename)
                for ri in rule_issues:
                    issues.append({
                        "file": filename,
                        "line": ri.line,
                        "column": ri.column,
                        "end_line": ri.end_line,
                        "rule_id": rule.rule_id,
                        "rule_name": rule.name,
                        "severity": rule.severity,
                        "category": rule.category,
                        "message": ri.message,
                        "suggestion": ri.suggestion,
                        "owasp_category": rule.owasp_category,
                        "code_snippet": ri.code_snippet,
                    })
            except Exception as e:
                print(f"[RuleEngine] Error running rule {rule.rule_id} on {filename}: {e}")
        return issues

    def get_rules_summary(self) -> List[Dict[str, str]]:
        """Return a summary of all loaded rules."""
        return [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "description": r.description,
                "severity": r.severity,
                "category": r.category,
                "owasp_category": r.owasp_category or "",
                "languages": ", ".join(r.languages),
            }
            for r in self.rules
        ]
