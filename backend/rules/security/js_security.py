"""
JavaScript Security Rules — Production-grade security checks for JS/TS code.
Covers OWASP Top 10 patterns detectable via static analysis.
"""
import re
from typing import List
from backend.rule_engine.base import BaseRule, RuleIssue
from backend.core.config import Severity, Category, OWASP


class JSXSSRule(BaseRule):
    rule_id = "JSEC001"
    name = "Cross-Site Scripting (XSS)"
    description = "Detects dangerous innerHTML, document.write, and eval usage with variables."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    owasp_category = OWASP.A03_INJECTION
    languages = ["javascript"]

    PATTERNS = [
        (re.compile(r'\.innerHTML\s*=\s*(?![\'"]\s*[\'"])'), "innerHTML assigned with dynamic value — XSS risk"),
        (re.compile(r'\.outerHTML\s*=\s*(?![\'"]\s*[\'"])'), "outerHTML assigned with dynamic value — XSS risk"),
        (re.compile(r'document\.write\s*\('), "document.write() can lead to XSS"),
        (re.compile(r'document\.writeln\s*\('), "document.writeln() can lead to XSS"),
        (re.compile(r'\beval\s*\('), "eval() executes arbitrary code — code injection risk"),
        (re.compile(r'new\s+Function\s*\('), "new Function() executes arbitrary code — code injection risk"),
        (re.compile(r'setTimeout\s*\(\s*[`\'"]'), "setTimeout with string argument executes arbitrary code"),
        (re.compile(r'setInterval\s*\(\s*[`\'"]'), "setInterval with string argument executes arbitrary code"),
        (re.compile(r'dangerouslySetInnerHTML'), "React dangerouslySetInnerHTML — XSS risk if unsanitized"),
    ]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('*'):
                continue
            for pattern, msg in self.PATTERNS:
                if pattern.search(line):
                    issues.append(RuleIssue(
                        file=filename, line=i,
                        message=msg,
                        suggestion="Sanitize user input with DOMPurify or use textContent instead of innerHTML.",
                        code_snippet=self.get_code_snippet(source_code, i),
                    ))
                    break
        return issues


class JSHardcodedSecretsRule(BaseRule):
    rule_id = "JSEC002"
    name = "Hardcoded Secrets (JS)"
    description = "Detects hardcoded API keys, tokens, and passwords in JavaScript/TypeScript."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    owasp_category = OWASP.A07_AUTH_FAILURES
    languages = ["javascript"]

    PATTERNS = [
        (re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']'), "Hardcoded password"),
        (re.compile(r'(?i)(api_key|apiKey|api_secret|apiSecret)\s*[:=]\s*["\'][^"\']{8,}["\']'), "Hardcoded API key"),
        (re.compile(r'(?i)(secret|secretKey|secret_key)\s*[:=]\s*["\'][^"\']{8,}["\']'), "Hardcoded secret"),
        (re.compile(r'(?i)(token|authToken|auth_token|accessToken|access_token)\s*[:=]\s*["\'][^"\']{8,}["\']'), "Hardcoded token"),
        (re.compile(r'(?i)(aws_access_key|aws_secret)\s*[:=]\s*["\'][^"\']+["\']'), "Hardcoded AWS credential"),
        (re.compile(r'(?i)private_key\s*[:=]\s*["\'][^"\']{8,}["\']'), "Hardcoded private key"),
        (re.compile(r'(?i)(db_pass|database_password|dbpassword)\s*[:=]\s*["\'][^"\']+["\']'), "Hardcoded DB password"),
    ]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('*'):
                continue
            for pattern, msg in self.PATTERNS:
                if pattern.search(line):
                    issues.append(RuleIssue(
                        file=filename, line=i,
                        message=f"{msg} detected in source code.",
                        suggestion="Use environment variables (process.env.SECRET) or a secrets manager.",
                        code_snippet=self.get_code_snippet(source_code, i),
                    ))
                    break
        return issues


class JSInsecureRandomRule(BaseRule):
    rule_id = "JSEC003"
    name = "Insecure Randomness"
    description = "Math.random() is not cryptographically secure."
    severity = Severity.MAJOR
    category = Category.SECURITY
    owasp_category = OWASP.A02_CRYPTOGRAPHIC_FAILURES
    languages = ["javascript"]

    PATTERN = re.compile(r'\bMath\.random\s*\(')

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            if self.PATTERN.search(line):
                issues.append(RuleIssue(
                    file=filename, line=i,
                    message="Math.random() is not cryptographically secure.",
                    suggestion="Use crypto.getRandomValues() or the Web Crypto API for security-sensitive randomness.",
                    code_snippet=self.get_code_snippet(source_code, i),
                ))
        return issues


class JSPrototypePollutionRule(BaseRule):
    rule_id = "JSEC004"
    name = "Prototype Pollution"
    description = "Detects patterns that may allow prototype pollution attacks."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    owasp_category = OWASP.A03_INJECTION
    languages = ["javascript"]

    PATTERNS = [
        re.compile(r'\[[\'"__proto__\'"]\]'),
        re.compile(r'__proto__\s*[=:]'),
        re.compile(r'Object\.assign\s*\(\s*\w+\.prototype'),
        re.compile(r'constructor\s*\.\s*prototype\s*\['),
    ]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            for pattern in self.PATTERNS:
                if pattern.search(line):
                    issues.append(RuleIssue(
                        file=filename, line=i,
                        message="Potential prototype pollution — __proto__ or prototype manipulation detected.",
                        suggestion="Validate and sanitize object keys. Use Object.create(null) for safe maps.",
                        code_snippet=self.get_code_snippet(source_code, i),
                    ))
                    break
        return issues


class JSPathTraversalRule(BaseRule):
    rule_id = "JSEC005"
    name = "Path Traversal (JS)"
    description = "Detects file path operations with user-controlled input."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    owasp_category = OWASP.A01_BROKEN_ACCESS_CONTROL
    languages = ["javascript"]

    PATTERNS = [
        re.compile(r'(?:fs|require\([\'"]fs[\'"]\))\s*\.\s*(?:readFile|writeFile|readFileSync|writeFileSync|unlink|rmdir)\s*\(\s*(?:req\.|params\.|query\.|body\.)'),
        re.compile(r'path\.join\s*\([^)]*(?:req\.|params\.|query\.|body\.)'),
        re.compile(r'path\.resolve\s*\([^)]*(?:req\.|params\.|query\.|body\.)'),
        re.compile(r'__dirname\s*\+\s*[^"\']+(?:req\.|params\.|query\.)'),
    ]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            for pattern in self.PATTERNS:
                if pattern.search(line):
                    issues.append(RuleIssue(
                        file=filename, line=i,
                        message="Potential path traversal — file operation with user-controlled path.",
                        suggestion="Validate and sanitize file paths. Use path.resolve() and verify the result stays within allowed directories.",
                        code_snippet=self.get_code_snippet(source_code, i),
                    ))
                    break
        return issues


class JSInsecureJWTRule(BaseRule):
    rule_id = "JSEC006"
    name = "Insecure JWT Usage"
    description = "Detects JWT verification bypasses and weak configurations."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    owasp_category = OWASP.A07_AUTH_FAILURES
    languages = ["javascript"]

    PATTERNS = [
        (re.compile(r'jwt\.verify\s*\([^)]*algorithms\s*:\s*\[[^\]]*none'), "JWT 'none' algorithm — authentication bypass"),
        (re.compile(r'jwt\.decode\s*\((?!.*verify)'), "jwt.decode() without verification — token not validated"),
        (re.compile(r'verify\s*:\s*false'), "JWT verification disabled"),
        (re.compile(r'ignoreExpiration\s*:\s*true'), "JWT expiration check disabled"),
    ]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            for pattern, msg in self.PATTERNS:
                if pattern.search(line):
                    issues.append(RuleIssue(
                        file=filename, line=i,
                        message=msg,
                        suggestion="Always verify JWT signatures with a strong algorithm (RS256/ES256). Never use 'none' algorithm.",
                        code_snippet=self.get_code_snippet(source_code, i),
                    ))
                    break
        return issues


class JSNoSQLInjectionRule(BaseRule):
    rule_id = "JSEC007"
    name = "NoSQL Injection"
    description = "Detects MongoDB/NoSQL queries built with user-controlled input."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    owasp_category = OWASP.A03_INJECTION
    languages = ["javascript"]

    PATTERNS = [
        re.compile(r'\.find\s*\(\s*(?:req\.|params\.|query\.|body\.)'),
        re.compile(r'\.findOne\s*\(\s*(?:req\.|params\.|query\.|body\.)'),
        re.compile(r'\.update\s*\(\s*(?:req\.|params\.|query\.|body\.)'),
        re.compile(r'\.deleteOne\s*\(\s*(?:req\.|params\.|query\.|body\.)'),
        re.compile(r'\$where\s*:\s*(?:req\.|params\.|query\.|body\.)'),
    ]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            for pattern in self.PATTERNS:
                if pattern.search(line):
                    issues.append(RuleIssue(
                        file=filename, line=i,
                        message="Potential NoSQL injection — query built with user-controlled input.",
                        suggestion="Sanitize and validate all query inputs. Use mongoose schema validation.",
                        code_snippet=self.get_code_snippet(source_code, i),
                    ))
                    break
        return issues


class JSInsecureCORSRule(BaseRule):
    rule_id = "JSEC008"
    name = "Insecure CORS Configuration"
    description = "Detects overly permissive CORS settings."
    severity = Severity.MAJOR
    category = Category.SECURITY
    owasp_category = OWASP.A05_SECURITY_MISCONFIGURATION
    languages = ["javascript"]

    PATTERNS = [
        (re.compile(r'Access-Control-Allow-Origin[\'"\s]*:\s*[\'"]?\*'), "Wildcard CORS origin allows any domain"),
        (re.compile(r'origin\s*:\s*[\'"]?\*[\'"]?'), "CORS origin set to wildcard '*'"),
        (re.compile(r'cors\s*\(\s*\)'), "cors() called without configuration — defaults to wildcard"),
        (re.compile(r'Access-Control-Allow-Credentials[\'"\s]*:\s*[\'"]?true'), "CORS credentials allowed — verify origin is not wildcard"),
    ]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            for pattern, msg in self.PATTERNS:
                if pattern.search(line):
                    issues.append(RuleIssue(
                        file=filename, line=i,
                        message=msg,
                        suggestion="Restrict CORS to specific trusted origins. Never combine wildcard origin with credentials.",
                        code_snippet=self.get_code_snippet(source_code, i),
                    ))
                    break
        return issues


class JSDebugCodeRule(BaseRule):
    rule_id = "JSEC009"
    name = "Debug Code in Production"
    description = "Detects console.log, debugger statements, and TODO security notes."
    severity = Severity.MINOR
    category = Category.SECURITY
    owasp_category = OWASP.A09_LOGGING_FAILURES
    languages = ["javascript"]

    PATTERNS = [
        (re.compile(r'\bconsole\.(log|debug|info|warn|error)\s*\('), "console statement leaks information"),
        (re.compile(r'\bdebugger\b'), "debugger statement left in code"),
    ]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('*'):
                continue
            for pattern, msg in self.PATTERNS:
                if pattern.search(line):
                    issues.append(RuleIssue(
                        file=filename, line=i,
                        message=f"{msg} — remove before production deployment.",
                        suggestion="Remove debug statements. Use a proper logging library with log levels.",
                        code_snippet=self.get_code_snippet(source_code, i),
                    ))
                    break
        return issues


class JSReDoSRule(BaseRule):
    rule_id = "JSEC010"
    name = "ReDoS — Catastrophic Backtracking"
    description = "Detects regex patterns vulnerable to catastrophic backtracking."
    severity = Severity.MAJOR
    category = Category.SECURITY
    owasp_category = OWASP.A04_INSECURE_DESIGN
    languages = ["javascript"]

    # Patterns that indicate potentially vulnerable regex: nested quantifiers
    REDOS_PATTERN = re.compile(r'(?:new\s+RegExp|/)[^/]*(?:\+|\*|\{[0-9,]+\})[^/]*(?:\+|\*|\{[0-9,]+\})[^/]*/[gimsuy]*')

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            if self.REDOS_PATTERN.search(line):
                issues.append(RuleIssue(
                    file=filename, line=i,
                    message="Potentially vulnerable regex — nested quantifiers may cause catastrophic backtracking (ReDoS).",
                    suggestion="Simplify the regex or use a safe regex library. Test with tools like safe-regex.",
                    code_snippet=self.get_code_snippet(source_code, i),
                ))
        return issues


class JSOpenRedirectRule(BaseRule):
    rule_id = "JSEC011"
    name = "Open Redirect"
    description = "Detects redirects using user-controlled URLs."
    severity = Severity.MAJOR
    category = Category.SECURITY
    owasp_category = OWASP.A01_BROKEN_ACCESS_CONTROL
    languages = ["javascript"]

    PATTERNS = [
        re.compile(r'res\.redirect\s*\(\s*(?:req\.|params\.|query\.|body\.)'),
        re.compile(r'window\.location\s*=\s*(?:req\.|params\.|query\.|body\.|[a-zA-Z_$]\w*(?:Url|URL|Redirect|redirect))'),
        re.compile(r'location\.href\s*=\s*(?:req\.|params\.|query\.|body\.)'),
    ]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            for pattern in self.PATTERNS:
                if pattern.search(line):
                    issues.append(RuleIssue(
                        file=filename, line=i,
                        message="Potential open redirect — redirect target may be user-controlled.",
                        suggestion="Validate redirect URLs against an allowlist of trusted domains.",
                        code_snippet=self.get_code_snippet(source_code, i),
                    ))
                    break
        return issues


class JSMissingHelmetRule(BaseRule):
    rule_id = "JSEC012"
    name = "Missing Security Headers (Helmet)"
    description = "Express apps should use helmet to set security headers."
    severity = Severity.MAJOR
    category = Category.SECURITY
    owasp_category = OWASP.A05_SECURITY_MISCONFIGURATION
    languages = ["javascript"]

    EXPRESS_PATTERN = re.compile(r'(?:require\([\'"]express[\'"]\)|from\s+[\'"]express[\'"])')
    HELMET_PATTERN = re.compile(r'(?:require\([\'"]helmet[\'"]\)|from\s+[\'"]helmet[\'"]|app\.use\s*\(\s*helmet)')

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if self.EXPRESS_PATTERN.search(source_code) and not self.HELMET_PATTERN.search(source_code):
            issues.append(RuleIssue(
                file=filename, line=1,
                message="Express app detected without helmet — security headers not set.",
                suggestion="Add `const helmet = require('helmet'); app.use(helmet());` to set security headers.",
                code_snippet=self.get_code_snippet(source_code, 1),
            ))
        return issues


class JSSSRFRule(BaseRule):
    rule_id = "JSEC013"
    name = "Server-Side Request Forgery (JS)"
    description = "Detects HTTP requests with user-controlled URLs."
    severity = Severity.MAJOR
    category = Category.SECURITY
    owasp_category = OWASP.A10_SSRF
    languages = ["javascript"]

    PATTERNS = [
        re.compile(r'(?:fetch|axios\.get|axios\.post|http\.get|https\.get|request\.get)\s*\(\s*(?:req\.|params\.|query\.|body\.|`[^`]*\$\{)'),
        re.compile(r'(?:fetch|axios)\s*\(\s*(?:req\.|params\.|query\.|body\.)'),
    ]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            for pattern in self.PATTERNS:
                if pattern.search(line):
                    issues.append(RuleIssue(
                        file=filename, line=i,
                        message="Potential SSRF — HTTP request with user-controlled URL.",
                        suggestion="Validate and whitelist URLs. Block requests to internal IP ranges (169.254.x.x, 10.x.x.x, etc.).",
                        code_snippet=self.get_code_snippet(source_code, i),
                    ))
                    break
        return issues
