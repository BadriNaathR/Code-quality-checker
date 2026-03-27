"""
Additional Python Security Rules — Production-grade checks beyond injection.
"""
import ast
import re
from typing import List
from backend.rule_engine.base import BaseRule, RuleIssue
from backend.core.config import Severity, Category, OWASP


class PathTraversalRule(BaseRule):
    rule_id = "SEC009"
    name = "Path Traversal"
    description = "Detects file operations with user-controlled paths."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    owasp_category = OWASP.A01_BROKEN_ACCESS_CONTROL
    languages = ["python"]

    FILE_OPS = {"open", "os.path.join", "os.path.abspath", "shutil.copy", "shutil.move"}

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues

        USER_INPUT_SOURCES = {
            "request.args", "request.form", "request.json", "request.data",
            "request.GET", "request.POST", "input", "sys.argv",
        }

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)
                if func_name in self.FILE_OPS:
                    for arg in node.args:
                        arg_src = ast.get_source_segment(source_code, arg) or ""
                        if any(src in arg_src for src in USER_INPUT_SOURCES):
                            issues.append(RuleIssue(
                                file=filename, line=node.lineno, column=node.col_offset,
                                message=f"Potential path traversal in {func_name}() with user-controlled input.",
                                suggestion="Validate paths with os.path.realpath() and ensure they stay within allowed directories.",
                                code_snippet=self.get_code_snippet(source_code, node.lineno),
                            ))
                            break
        return issues

    def _get_func_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""


class XXERule(BaseRule):
    rule_id = "SEC010"
    name = "XML External Entity (XXE)"
    description = "Detects unsafe XML parsing that may allow XXE attacks."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    owasp_category = OWASP.A05_SECURITY_MISCONFIGURATION
    languages = ["python"]

    UNSAFE_PARSERS = {
        "xml.etree.ElementTree.parse",
        "xml.etree.ElementTree.fromstring",
        "xml.dom.minidom.parse",
        "xml.dom.minidom.parseString",
        "lxml.etree.parse",
        "lxml.etree.fromstring",
    }

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)
                if func_name in self.UNSAFE_PARSERS:
                    issues.append(RuleIssue(
                        file=filename, line=node.lineno, column=node.col_offset,
                        message=f"Unsafe XML parser {func_name}() — may be vulnerable to XXE attacks.",
                        suggestion="Use defusedxml library: `import defusedxml.ElementTree as ET`.",
                        code_snippet=self.get_code_snippet(source_code, node.lineno),
                    ))
        return issues

    def _get_func_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""


class InsecureTLSRule(BaseRule):
    rule_id = "SEC011"
    name = "Insecure TLS/SSL Configuration"
    description = "Detects disabled SSL verification and weak TLS settings."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    owasp_category = OWASP.A02_CRYPTOGRAPHIC_FAILURES
    languages = ["python"]

    PATTERNS = [
        (re.compile(r'verify\s*=\s*False'), "SSL certificate verification disabled"),
        (re.compile(r'ssl\.CERT_NONE'), "SSL certificate validation set to CERT_NONE"),
        (re.compile(r'ssl\.PROTOCOL_SSLv2|ssl\.PROTOCOL_SSLv3|ssl\.PROTOCOL_TLSv1\b'), "Deprecated/insecure SSL/TLS protocol version"),
        (re.compile(r'check_hostname\s*=\s*False'), "SSL hostname check disabled"),
        (re.compile(r'VERIFY_NONE'), "SSL verification disabled"),
    ]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            for pattern, msg in self.PATTERNS:
                if pattern.search(line):
                    issues.append(RuleIssue(
                        file=filename, line=i,
                        message=f"{msg} — man-in-the-middle attack risk.",
                        suggestion="Always verify SSL certificates. Use verify=True and keep TLS version >= 1.2.",
                        code_snippet=self.get_code_snippet(source_code, i),
                    ))
                    break
        return issues


class MissingAuthDecoratorRule(BaseRule):
    rule_id = "SEC012"
    name = "Missing Authentication Decorator"
    description = "Flask/FastAPI routes without authentication decorators may be publicly accessible."
    severity = Severity.MAJOR
    category = Category.SECURITY
    owasp_category = OWASP.A01_BROKEN_ACCESS_CONTROL
    languages = ["python"]

    ROUTE_PATTERNS = [
        re.compile(r'@app\.(?:route|get|post|put|delete|patch)\s*\('),
        re.compile(r'@router\.(?:get|post|put|delete|patch)\s*\('),
        re.compile(r'@blueprint\.(?:route|get|post|put|delete|patch)\s*\('),
    ]
    AUTH_PATTERNS = [
        re.compile(r'@(?:login_required|require_auth|jwt_required|requires_auth|auth\.login_required|Depends\(get_current_user\))'),
        re.compile(r'Depends\s*\('),
        re.compile(r'@permission_required'),
    ]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        lines = source_code.splitlines()
        for i, line in enumerate(lines):
            is_route = any(p.search(line) for p in self.ROUTE_PATTERNS)
            if not is_route:
                continue
            # Check surrounding decorators (up to 5 lines before)
            context = "\n".join(lines[max(0, i - 5):i + 10])
            has_auth = any(p.search(context) for p in self.AUTH_PATTERNS)
            if not has_auth:
                issues.append(RuleIssue(
                    file=filename, line=i + 1,
                    message="Route defined without visible authentication decorator.",
                    suggestion="Add authentication: @login_required, @jwt_required, or FastAPI Depends(get_current_user).",
                    code_snippet=self.get_code_snippet(source_code, i + 1),
                ))
        return issues


class SensitiveDataLoggingRule(BaseRule):
    rule_id = "SEC013"
    name = "Sensitive Data in Logs"
    description = "Detects logging of potentially sensitive data like passwords or tokens."
    severity = Severity.MAJOR
    category = Category.SECURITY
    owasp_category = OWASP.A09_LOGGING_FAILURES
    languages = ["python"]

    PATTERNS = [
        re.compile(r'(?:logging|logger|log)\.\w+\s*\([^)]*(?:password|passwd|token|secret|key|credential)', re.IGNORECASE),
        re.compile(r'print\s*\([^)]*(?:password|passwd|token|secret|api_key)', re.IGNORECASE),
    ]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            for pattern in self.PATTERNS:
                if pattern.search(line):
                    issues.append(RuleIssue(
                        file=filename, line=i,
                        message="Potentially sensitive data being logged.",
                        suggestion="Never log passwords, tokens, or secrets. Mask or redact sensitive fields.",
                        code_snippet=self.get_code_snippet(source_code, i),
                    ))
                    break
        return issues


class RaceConditionRule(BaseRule):
    rule_id = "SEC014"
    name = "TOCTOU Race Condition"
    description = "Detects time-of-check/time-of-use patterns with file existence checks."
    severity = Severity.MAJOR
    category = Category.SECURITY
    owasp_category = OWASP.A04_INSECURE_DESIGN
    languages = ["python"]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.If):
                # Check for os.path.exists() followed by open() in same block
                cond_src = ast.get_source_segment(source_code, node.test) or ""
                if "os.path.exists" in cond_src or "os.path.isfile" in cond_src:
                    body_src = "\n".join(
                        ast.get_source_segment(source_code, s) or "" for s in node.body
                    )
                    if "open(" in body_src:
                        issues.append(RuleIssue(
                            file=filename, line=node.lineno,
                            message="TOCTOU race condition — file existence check followed by file operation.",
                            suggestion="Use try/except around the file operation instead of checking existence first.",
                            code_snippet=self.get_code_snippet(source_code, node.lineno),
                        ))
        return issues
