"""
Security Rules — Detect OWASP Top 10 and common security vulnerabilities in Python code.
"""
import ast
import re
from typing import List
from backend.rule_engine.base import BaseRule, RuleIssue
from backend.core.config import Severity, Category, OWASP


class SQLInjectionRule(BaseRule):
    rule_id = "SEC001"
    name = "SQL Injection"
    description = "Detects string formatting/concatenation used in SQL queries."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    owasp_category = OWASP.A03_INJECTION
    languages = ["python"]

    SQL_KEYWORDS = re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b', re.IGNORECASE)

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues

        for node in ast.walk(ast_tree):
            # Check f-strings containing SQL keywords
            if isinstance(node, ast.JoinedStr):
                reconstructed = ast.get_source_segment(source_code, node) or ""
                if self.SQL_KEYWORDS.search(reconstructed):
                    issues.append(RuleIssue(
                        file=filename, line=node.lineno, column=node.col_offset,
                        message="Potential SQL injection via f-string formatting.",
                        suggestion="Use parameterized queries instead of string formatting.",
                        code_snippet=self.get_code_snippet(source_code, node.lineno),
                    ))
            # Check % formatting: "SELECT ... %s" % var
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                    if self.SQL_KEYWORDS.search(node.left.value):
                        issues.append(RuleIssue(
                            file=filename, line=node.lineno, column=node.col_offset,
                            message="Potential SQL injection via % string formatting.",
                            suggestion="Use parameterized queries instead of % formatting.",
                            code_snippet=self.get_code_snippet(source_code, node.lineno),
                        ))
            # Check .format() on SQL strings
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == 'format' and isinstance(node.func.value, ast.Constant):
                    if isinstance(node.func.value.value, str) and self.SQL_KEYWORDS.search(node.func.value.value):
                        issues.append(RuleIssue(
                            file=filename, line=node.lineno, column=node.col_offset,
                            message="Potential SQL injection via .format() string formatting.",
                            suggestion="Use parameterized queries instead of .format().",
                            code_snippet=self.get_code_snippet(source_code, node.lineno),
                        ))
        return issues


class CommandInjectionRule(BaseRule):
    rule_id = "SEC002"
    name = "OS Command Injection"
    description = "Detects use of os.system, subprocess with shell=True, or eval/exec."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    owasp_category = OWASP.A03_INJECTION
    languages = ["python"]

    DANGEROUS_FUNCS = {"system", "popen", "popen2", "popen3", "popen4"}
    DANGEROUS_CALLS = {"eval", "exec", "compile", "__import__"}

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)
                if not func_name:
                    continue

                # os.system(), os.popen(), etc.
                if func_name.split(".")[-1] in self.DANGEROUS_FUNCS:
                    issues.append(RuleIssue(
                        file=filename, line=node.lineno, column=node.col_offset,
                        message=f"Dangerous function call: {func_name}() can lead to OS command injection.",
                        suggestion="Use subprocess.run() with a list of arguments and shell=False.",
                        code_snippet=self.get_code_snippet(source_code, node.lineno),
                    ))

                # eval(), exec(), compile()
                if func_name in self.DANGEROUS_CALLS:
                    issues.append(RuleIssue(
                        file=filename, line=node.lineno, column=node.col_offset,
                        message=f"Use of {func_name}() detected — potential code injection risk.",
                        suggestion=f"Avoid {func_name}(). Use safer alternatives like ast.literal_eval() for eval.",
                        code_snippet=self.get_code_snippet(source_code, node.lineno),
                    ))

                # subprocess with shell=True
                if func_name in ("subprocess.call", "subprocess.run", "subprocess.Popen", "subprocess.check_output"):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            issues.append(RuleIssue(
                                file=filename, line=node.lineno, column=node.col_offset,
                                message=f"{func_name}() called with shell=True — command injection risk.",
                                suggestion="Use shell=False and pass arguments as a list.",
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


class HardcodedSecretsRule(BaseRule):
    rule_id = "SEC003"
    name = "Hardcoded Secrets"
    description = "Detects hardcoded passwords, API keys, tokens, and secret keys."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    owasp_category = OWASP.A07_AUTH_FAILURES
    languages = ["python", "javascript"]

    SECRET_PATTERNS = [
        (re.compile(r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']'), "Hardcoded password detected"),
        (re.compile(r'(?i)(api_key|apikey|api_secret)\s*=\s*["\'][^"\']+["\']'), "Hardcoded API key detected"),
        (re.compile(r'(?i)(secret_key|secretkey|secret)\s*=\s*["\'][^"\']+["\']'), "Hardcoded secret key detected"),
        (re.compile(r'(?i)(token|auth_token|access_token)\s*=\s*["\'][^"\']+["\']'), "Hardcoded token detected"),
        (re.compile(r'(?i)(private_key|priv_key)\s*=\s*["\'][^"\']+["\']'), "Hardcoded private key detected"),
        (re.compile(r'(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*["\'][^"\']+["\']'), "Hardcoded AWS credential"),
        (re.compile(r'(?i)(db_password|database_password)\s*=\s*["\'][^"\']+["\']'), "Hardcoded database password"),
    ]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            for pattern, msg in self.SECRET_PATTERNS:
                if pattern.search(line):
                    issues.append(RuleIssue(
                        file=filename, line=i,
                        message=msg,
                        suggestion="Use environment variables or a secrets manager instead of hardcoding secrets.",
                        code_snippet=self.get_code_snippet(source_code, i),
                    ))
                    break  # One issue per line
        return issues


class InsecureDeserializationRule(BaseRule):
    rule_id = "SEC004"
    name = "Insecure Deserialization"
    description = "Detects use of pickle, marshal, yaml.load(unsafe), and shelve."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    owasp_category = OWASP.A08_DATA_INTEGRITY_FAILURES
    languages = ["python"]

    UNSAFE_FUNCS = {"pickle.load", "pickle.loads", "marshal.load", "marshal.loads",
                    "shelve.open", "cPickle.load", "cPickle.loads"}

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)
                if func_name in self.UNSAFE_FUNCS:
                    issues.append(RuleIssue(
                        file=filename, line=node.lineno, column=node.col_offset,
                        message=f"Insecure deserialization via {func_name}().",
                        suggestion="Use JSON or other safe serialization formats. If pickle is required, validate the source.",
                        code_snippet=self.get_code_snippet(source_code, node.lineno),
                    ))
                # yaml.load without Loader=SafeLoader
                if func_name in ("yaml.load", "yaml.unsafe_load"):
                    has_safe_loader = any(
                        kw.arg == "Loader" and isinstance(kw.value, ast.Attribute)
                        and kw.value.attr == "SafeLoader"
                        for kw in node.keywords
                    )
                    if not has_safe_loader and func_name == "yaml.load":
                        issues.append(RuleIssue(
                            file=filename, line=node.lineno, column=node.col_offset,
                            message="yaml.load() without SafeLoader — potential arbitrary code execution.",
                            suggestion="Use yaml.safe_load() or pass Loader=yaml.SafeLoader.",
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


class WeakCryptographyRule(BaseRule):
    rule_id = "SEC005"
    name = "Weak Cryptography"
    description = "Detects use of weak hashing algorithms (MD5, SHA1) and insecure random."
    severity = Severity.MAJOR
    category = Category.SECURITY
    owasp_category = OWASP.A02_CRYPTOGRAPHIC_FAILURES
    languages = ["python"]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)
                # Weak hash functions
                if func_name in ("hashlib.md5", "hashlib.sha1"):
                    issues.append(RuleIssue(
                        file=filename, line=node.lineno, column=node.col_offset,
                        message=f"Weak hash algorithm: {func_name}() is not collision-resistant.",
                        suggestion="Use hashlib.sha256() or hashlib.sha3_256() for security-critical hashing.",
                        code_snippet=self.get_code_snippet(source_code, node.lineno),
                    ))
                # Insecure random for security
                if func_name in ("random.random", "random.randint", "random.choice", "random.randrange"):
                    issues.append(RuleIssue(
                        file=filename, line=node.lineno, column=node.col_offset,
                        message=f"{func_name}() is not cryptographically secure.",
                        suggestion="Use secrets module (secrets.token_hex(), secrets.randbelow()) for security-sensitive randomness.",
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


class SSRFRule(BaseRule):
    rule_id = "SEC006"
    name = "Server-Side Request Forgery (SSRF)"
    description = "Detects HTTP requests where the URL may be user-controlled."
    severity = Severity.MAJOR
    category = Category.SECURITY
    owasp_category = OWASP.A10_SSRF
    languages = ["python"]

    HTTP_FUNCS = {"requests.get", "requests.post", "requests.put", "requests.delete", "requests.patch",
                  "urllib.request.urlopen", "httpx.get", "httpx.post", "httpx.AsyncClient.get"}

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                func_name = self._get_func_name(node)
                if func_name in self.HTTP_FUNCS:
                    # Check if the first argument is a variable (potentially user-controlled)
                    if node.args and isinstance(node.args[0], ast.Name):
                        issues.append(RuleIssue(
                            file=filename, line=node.lineno, column=node.col_offset,
                            message=f"Potential SSRF: {func_name}() called with a variable URL.",
                            suggestion="Validate and whitelist URLs before making HTTP requests.",
                            code_snippet=self.get_code_snippet(source_code, node.lineno),
                        ))
                    elif node.args and isinstance(node.args[0], ast.JoinedStr):
                        issues.append(RuleIssue(
                            file=filename, line=node.lineno, column=node.col_offset,
                            message=f"Potential SSRF: {func_name}() called with f-string URL.",
                            suggestion="Validate and whitelist URLs before making HTTP requests.",
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


class MissingSecurityLoggingRule(BaseRule):
    rule_id = "SEC007"
    name = "Missing Security Logging"
    description = "Detects except blocks that catch SecurityError or auth-related exceptions silently."
    severity = Severity.MINOR
    category = Category.SECURITY
    owasp_category = OWASP.A09_LOGGING_FAILURES
    languages = ["python"]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues

        for node in ast.walk(ast_tree):
            # Bare except or except Exception with pass/... body
            if isinstance(node, ast.ExceptHandler):
                body_is_pass = (
                    len(node.body) == 1
                    and isinstance(node.body[0], (ast.Pass, ast.Expr))
                    and (isinstance(node.body[0], ast.Pass) or
                         (isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant)))
                )
                if body_is_pass:
                    issues.append(RuleIssue(
                        file=filename, line=node.lineno, column=node.col_offset,
                        message="Silent exception handler — exceptions are caught but not logged.",
                        suggestion="Log the exception with logging.exception() or logging.error() to maintain an audit trail.",
                        code_snippet=self.get_code_snippet(source_code, node.lineno),
                    ))
        return issues


class DebugModeEnabledRule(BaseRule):
    rule_id = "SEC008"
    name = "Debug Mode Enabled"
    description = "Detects Flask/Django debug mode enabled in production."
    severity = Severity.MAJOR
    category = Category.SECURITY
    owasp_category = OWASP.A05_SECURITY_MISCONFIGURATION
    languages = ["python"]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                # app.run(debug=True)
                for kw in node.keywords:
                    if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        issues.append(RuleIssue(
                            file=filename, line=node.lineno, column=node.col_offset,
                            message="Debug mode is enabled — exposes sensitive information in production.",
                            suggestion="Set debug=False for production deployments.",
                            code_snippet=self.get_code_snippet(source_code, node.lineno),
                        ))
            # DEBUG = True
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "DEBUG":
                        if isinstance(node.value, ast.Constant) and node.value.value is True:
                            issues.append(RuleIssue(
                                file=filename, line=node.lineno, column=node.col_offset,
                                message="DEBUG = True detected — should be False in production.",
                                suggestion="Use environment variables: DEBUG = os.getenv('DEBUG', 'False') == 'True'",
                                code_snippet=self.get_code_snippet(source_code, node.lineno),
                            ))
        return issues
