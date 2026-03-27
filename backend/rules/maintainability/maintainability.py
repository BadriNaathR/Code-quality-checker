"""
Maintainability Rules — Dead code, missing docstrings, too many returns,
duplicate string literals, and long parameter lists for Python.
"""
import ast
import re
from typing import List
from backend.rule_engine.base import BaseRule, RuleIssue
from backend.core.config import Severity, Category


class DeadCodeAfterReturnRule(BaseRule):
    rule_id = "MAINT001"
    name = "Dead Code After Return/Raise"
    description = "Statements after return/raise/break/continue are never executed."
    severity = Severity.MAJOR
    category = Category.MAINTAINABILITY
    languages = ["python"]

    _terminators = (ast.Return, ast.Raise, ast.Break, ast.Continue)

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues
        for node in ast.walk(ast_tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                     ast.For, ast.While, ast.If, ast.With,
                                     ast.Try, ast.Module)):
                continue
            body = getattr(node, "body", [])
            for i, stmt in enumerate(body):
                if isinstance(stmt, self._terminators) and i + 1 < len(body):
                    next_stmt = body[i + 1]
                    # Skip if next is just a docstring / pass
                    if isinstance(next_stmt, ast.Pass):
                        continue
                    if (isinstance(next_stmt, ast.Expr)
                            and isinstance(next_stmt.value, ast.Constant)
                            and isinstance(next_stmt.value.value, str)):
                        continue
                    issues.append(RuleIssue(
                        file=filename,
                        line=next_stmt.lineno,
                        message=f"Dead code — statement after {type(stmt).__name__.lower()} is unreachable.",
                        suggestion="Remove unreachable code or restructure the logic.",
                        code_snippet=self.get_code_snippet(source_code, next_stmt.lineno),
                    ))
        return issues


class MissingDocstringRule(BaseRule):
    rule_id = "MAINT002"
    name = "Missing Docstring"
    description = "Public functions, classes, and modules should have docstrings."
    severity = Severity.MINOR
    category = Category.MAINTAINABILITY
    languages = ["python"]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues

        def _has_docstring(node) -> bool:
            return (
                isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ) if node.body else False

        for node in ast.walk(ast_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Only flag public functions (not _private or __dunder__)
                if node.name.startswith("_"):
                    continue
                if not _has_docstring(node):
                    issues.append(RuleIssue(
                        file=filename,
                        line=node.lineno,
                        message=f"Public function '{node.name}' is missing a docstring.",
                        suggestion="Add a docstring describing the function's purpose, parameters, and return value.",
                        code_snippet=self.get_code_snippet(source_code, node.lineno),
                    ))
            elif isinstance(node, ast.ClassDef):
                if node.name.startswith("_"):
                    continue
                if not _has_docstring(node):
                    issues.append(RuleIssue(
                        file=filename,
                        line=node.lineno,
                        message=f"Class '{node.name}' is missing a docstring.",
                        suggestion="Add a docstring describing the class's purpose and usage.",
                        code_snippet=self.get_code_snippet(source_code, node.lineno),
                    ))
        return issues


class TooManyReturnStatementsRule(BaseRule):
    rule_id = "MAINT003"
    name = "Too Many Return Statements"
    description = "Functions with more than 4 return statements are hard to follow."
    severity = Severity.MINOR
    category = Category.MAINTAINABILITY
    languages = ["python"]

    MAX_RETURNS = 4

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues
        for node in ast.walk(ast_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                returns = [n for n in ast.walk(node) if isinstance(n, ast.Return)]
                if len(returns) > self.MAX_RETURNS:
                    issues.append(RuleIssue(
                        file=filename,
                        line=node.lineno,
                        message=f"Function '{node.name}' has {len(returns)} return statements (max {self.MAX_RETURNS}).",
                        suggestion="Simplify control flow — consider a single return at the end or extract sub-functions.",
                        code_snippet=self.get_code_snippet(source_code, node.lineno),
                    ))
        return issues


class DuplicateStringLiteralRule(BaseRule):
    rule_id = "MAINT004"
    name = "Duplicate String Literal"
    description = "The same string literal repeated 3+ times should be a named constant."
    severity = Severity.MINOR
    category = Category.MAINTAINABILITY
    languages = ["python"]

    MIN_LENGTH = 6
    MIN_OCCURRENCES = 3

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues

        from collections import Counter
        string_lines: dict = {}
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value.strip()
                if len(val) >= self.MIN_LENGTH:
                    if val not in string_lines:
                        string_lines[val] = []
                    string_lines[val].append(node.lineno)

        reported = set()
        for val, lines in string_lines.items():
            if len(lines) >= self.MIN_OCCURRENCES and val not in reported:
                reported.add(val)
                issues.append(RuleIssue(
                    file=filename,
                    line=lines[0],
                    message=f"String literal '{val[:40]}' repeated {len(lines)} times — extract to a named constant.",
                    suggestion=f"Define a module-level constant: MY_CONSTANT = '{val[:40]}' and reference it.",
                    code_snippet=self.get_code_snippet(source_code, lines[0]),
                ))
        return issues


class AssertForSecurityRule(BaseRule):
    rule_id = "MAINT005"
    name = "Assert Used for Security Check"
    description = "assert statements are stripped in optimized mode (-O) and must not be used for security/validation."
    severity = Severity.CRITICAL
    category = Category.MAINTAINABILITY
    languages = ["python"]

    _AUTH_KEYWORDS = re.compile(
        r'\b(auth|permission|role|admin|token|login|user|access|allowed|authorized)\b',
        re.IGNORECASE,
    )

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues
        lines = source_code.splitlines()
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Assert):
                line_src = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
                if self._AUTH_KEYWORDS.search(line_src):
                    issues.append(RuleIssue(
                        file=filename,
                        line=node.lineno,
                        message="assert used for security/auth check — disabled in optimized mode.",
                        suggestion="Replace with an explicit if/raise: if not condition: raise PermissionError(...)",
                        code_snippet=self.get_code_snippet(source_code, node.lineno),
                    ))
        return issues


class InsecureTempFileRule(BaseRule):
    rule_id = "MAINT006"
    name = "Insecure Temporary File"
    description = "tempfile.mktemp() is vulnerable to race conditions — use mkstemp() or NamedTemporaryFile()."
    severity = Severity.MAJOR
    category = Category.MAINTAINABILITY
    languages = ["python"]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = ""
                if isinstance(func, ast.Attribute):
                    name = func.attr
                elif isinstance(func, ast.Name):
                    name = func.id
                if name == "mktemp":
                    issues.append(RuleIssue(
                        file=filename,
                        line=node.lineno,
                        message="tempfile.mktemp() is insecure — race condition between name generation and file creation.",
                        suggestion="Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead.",
                        code_snippet=self.get_code_snippet(source_code, node.lineno),
                    ))
        return issues
