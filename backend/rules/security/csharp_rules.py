"""
C# / .NET Rules — Static analysis rules for .cs files.
Uses regex-based line scanning (no AST needed).
"""
import re
from typing import List
from backend.rule_engine.base import BaseRule, RuleIssue
from backend.core.config import Severity, Category, OWASP


class CSharpSQLInjectionRule(BaseRule):
    rule_id = "CS_SEC001"
    name = "C# SQL Injection"
    description = "Detects string concatenation used to build SQL queries in C#."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    owasp_category = OWASP.A03_INJECTION
    languages = ["csharp"]

    _pattern = re.compile(
        r'(\"|\+)\s*(SELECT|INSERT|UPDATE|DELETE|DROP|EXEC)\b.*(\+|\")',
        re.IGNORECASE
    )
    _string_format = re.compile(
        r'string\.(Format|Concat)\s*\(.*\b(SELECT|INSERT|UPDATE|DELETE)\b',
        re.IGNORECASE
    )
    _interpolation = re.compile(
        r'\$"[^"]*\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b',
        re.IGNORECASE
    )

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith('//'):
                continue
            if self._pattern.search(line) or self._string_format.search(line) or self._interpolation.search(line):
                issues.append(RuleIssue(
                    file=filename, line=i,
                    message="Potential SQL injection via string concatenation/interpolation.",
                    suggestion="Use parameterized queries (SqlParameter) or an ORM like Entity Framework.",
                    code_snippet=self.get_code_snippet(source_code, i),
                ))
        return issues


class CSharpHardcodedSecretsRule(BaseRule):
    rule_id = "CS_SEC002"
    name = "C# Hardcoded Secrets"
    description = "Detects hardcoded passwords, API keys, and connection strings in C# code."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    owasp_category = OWASP.A07_AUTH_FAILURES
    languages = ["csharp"]

    _patterns = [
        re.compile(r'(?i)(password|passwd|pwd)\s*=\s*"[^"]+"'),
        re.compile(r'(?i)(apikey|api_key|secret|token)\s*=\s*"[^"]+"'),
        re.compile(r'(?i)connectionstring\s*=\s*"[^"]*password=[^"]+"'),
        re.compile(r'(?i)(aws_access_key|aws_secret)\s*=\s*"[^"]+"'),
    ]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            if line.strip().startswith('//'):
                continue
            for pattern in self._patterns:
                if pattern.search(line):
                    issues.append(RuleIssue(
                        file=filename, line=i,
                        message="Hardcoded secret/credential detected in C# code.",
                        suggestion="Use environment variables, IConfiguration, or Azure Key Vault for secrets.",
                        code_snippet=self.get_code_snippet(source_code, i),
                    ))
                    break
        return issues


class CSharpWeakCryptoRule(BaseRule):
    rule_id = "CS_SEC003"
    name = "C# Weak Cryptography"
    description = "Detects use of MD5, SHA1, DES, or RC2 in C# code."
    severity = Severity.MAJOR
    category = Category.SECURITY
    owasp_category = OWASP.A02_CRYPTOGRAPHIC_FAILURES
    languages = ["csharp"]

    _pattern = re.compile(
        r'\b(MD5|SHA1|DESCryptoServiceProvider|RC2CryptoServiceProvider|TripleDES)\b'
        r'|new\s+(MD5CryptoServiceProvider|SHA1Managed)\s*\(',
        re.IGNORECASE
    )

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            if line.strip().startswith('//'):
                continue
            if self._pattern.search(line):
                issues.append(RuleIssue(
                    file=filename, line=i,
                    message="Weak cryptographic algorithm detected (MD5/SHA1/DES/RC2).",
                    suggestion="Use SHA256, SHA512, or AES (AesCryptoServiceProvider) instead.",
                    code_snippet=self.get_code_snippet(source_code, i),
                ))
        return issues


class CSharpEmptyCatchRule(BaseRule):
    rule_id = "CS_SEC004"
    name = "C# Empty Catch Block"
    description = "Detects empty catch blocks that silently swallow exceptions."
    severity = Severity.MAJOR
    category = Category.CODE_SMELL
    owasp_category = OWASP.A09_LOGGING_FAILURES
    languages = ["csharp"]

    _catch = re.compile(r'\bcatch\b\s*(\([^)]*\))?\s*\{')

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        lines = source_code.splitlines()
        for i, line in enumerate(lines, 1):
            if self._catch.search(line):
                # Look ahead for empty block: next non-whitespace line is '}'
                j = i  # 0-based index of next line
                while j < len(lines) and lines[j].strip() == '':
                    j += 1
                if j < len(lines) and lines[j].strip() == '}':
                    issues.append(RuleIssue(
                        file=filename, line=i,
                        message="Empty catch block — exception is silently swallowed.",
                        suggestion="Log the exception or handle it explicitly. Never silently ignore exceptions.",
                        code_snippet=self.get_code_snippet(source_code, i),
                    ))
        return issues


class CSharpDebugAttributeRule(BaseRule):
    rule_id = "CS_SEC005"
    name = "C# Debug/Trace Code Left In"
    description = "Detects Console.WriteLine, Debug.WriteLine, or [Conditional(\"DEBUG\")] in production code."
    severity = Severity.MINOR
    category = Category.CODE_SMELL
    owasp_category = None
    languages = ["csharp"]

    _pattern = re.compile(
        r'\b(Console\.Write(Line)?|Debug\.Write(Line)?|Trace\.Write(Line)?)\s*\(',
        re.IGNORECASE
    )

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            if line.strip().startswith('//'):
                continue
            if self._pattern.search(line):
                issues.append(RuleIssue(
                    file=filename, line=i,
                    message="Debug/Console output statement found — should not be in production code.",
                    suggestion="Use a proper logging framework (ILogger, Serilog, NLog) instead of Console/Debug output.",
                    code_snippet=self.get_code_snippet(source_code, i),
                ))
        return issues


class CSharpCommandInjectionRule(BaseRule):
    rule_id = "CS_SEC006"
    name = "C# Command Injection"
    description = "Detects Process.Start with user-controlled arguments."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    owasp_category = OWASP.A03_INJECTION
    languages = ["csharp"]

    _pattern = re.compile(r'Process\.Start\s*\(', re.IGNORECASE)

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            if line.strip().startswith('//'):
                continue
            if self._pattern.search(line):
                issues.append(RuleIssue(
                    file=filename, line=i,
                    message="Process.Start() detected — potential command injection if arguments are user-controlled.",
                    suggestion="Validate and sanitize all inputs before passing to Process.Start(). Avoid shell execution.",
                    code_snippet=self.get_code_snippet(source_code, i),
                ))
        return issues


class CSharpInsecureDeserializationRule(BaseRule):
    rule_id = "CS_SEC007"
    name = "C# Insecure Deserialization"
    description = "Detects use of BinaryFormatter or JavaScriptSerializer which are insecure."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    owasp_category = OWASP.A08_DATA_INTEGRITY_FAILURES
    languages = ["csharp"]

    _pattern = re.compile(r'\b(BinaryFormatter|JavaScriptSerializer|LosFormatter|ObjectStateFormatter)\b')

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            if line.strip().startswith('//'):
                continue
            if self._pattern.search(line):
                issues.append(RuleIssue(
                    file=filename, line=i,
                    message=f"Insecure deserializer detected — vulnerable to remote code execution.",
                    suggestion="Use System.Text.Json or Newtonsoft.Json with TypeNameHandling.None instead.",
                    code_snippet=self.get_code_snippet(source_code, i),
                ))
        return issues
