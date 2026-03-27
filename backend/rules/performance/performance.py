"""
Performance Rules — Detect potential performance issues in Python code.
"""
import ast
import re
from typing import List
from backend.rule_engine.base import BaseRule, RuleIssue
from backend.core.config import Severity, Category


class ListComprehensionInLoopRule(BaseRule):
    rule_id = "PERF001"
    name = "Inefficient Pattern in Loop"
    description = "Detects patterns like repeated list concatenation inside loops."
    severity = Severity.MINOR
    category = Category.PERFORMANCE
    languages = ["python"]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues
        for node in ast.walk(ast_tree):
            if isinstance(node, (ast.For, ast.While)):
                for child in ast.walk(node):
                    # list += [item] inside loop
                    if isinstance(child, ast.AugAssign) and isinstance(child.op, ast.Add):
                        if isinstance(child.value, ast.List):
                            issues.append(RuleIssue(
                                file=filename, line=child.lineno,
                                message="List concatenation inside loop — use .append() or .extend() instead.",
                                suggestion="Replace `lst += [item]` with `lst.append(item)` for better performance.",
                                code_snippet=self.get_code_snippet(source_code, child.lineno),
                            ))
        return issues


class MutableDefaultArgumentRule(BaseRule):
    rule_id = "PERF002"
    name = "Mutable Default Argument"
    description = "Detects mutable default arguments (list, dict, set) in function signatures."
    severity = Severity.MAJOR
    category = Category.CODE_SMELL
    languages = ["python"]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues
        for node in ast.walk(ast_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for default in node.args.defaults + node.args.kw_defaults:
                    if default is None:
                        continue
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        issues.append(RuleIssue(
                            file=filename, line=node.lineno,
                            message=f"Function '{node.name}' has a mutable default argument.",
                            suggestion="Use None as default and initialize inside the function: if arg is None: arg = []",
                            code_snippet=self.get_code_snippet(source_code, node.lineno),
                        ))
        return issues


class StarImportRule(BaseRule):
    rule_id = "PERF003"
    name = "Star Import"
    description = "Detects wildcard imports (from module import *) which pollute the namespace."
    severity = Severity.MINOR
    category = Category.CODE_SMELL
    languages = ["python"]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == '*':
                        issues.append(RuleIssue(
                            file=filename, line=node.lineno,
                            message=f"Wildcard import: from {node.module} import *",
                            suggestion="Import specific names to avoid namespace pollution and improve readability.",
                            code_snippet=self.get_code_snippet(source_code, node.lineno),
                        ))
        return issues
