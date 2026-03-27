"""
JavaScript Code Quality Rules — Production-grade code smell and maintainability checks.
"""
import re
from typing import List
from backend.rule_engine.base import BaseRule, RuleIssue
from backend.core.config import Severity, Category


class JSFunctionTooLongRule(BaseRule):
    rule_id = "JSCS001"
    name = "Function Too Long (JS)"
    description = "Functions exceeding 50 lines are hard to maintain."
    severity = Severity.MINOR
    category = Category.CODE_SMELL
    languages = ["javascript"]

    MAX_LINES = 50

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if not ast_tree or "functions" not in ast_tree:
            return issues
        lines = source_code.splitlines()
        for func in ast_tree.get("functions", []):
            # Estimate function length by counting lines until next function or EOF
            start = func.line - 1
            brace_count = 0
            end = start
            found_open = False
            for idx in range(start, len(lines)):
                brace_count += lines[idx].count('{') - lines[idx].count('}')
                if brace_count > 0:
                    found_open = True
                if found_open and brace_count <= 0:
                    end = idx
                    break
            length = end - start + 1
            if length > self.MAX_LINES:
                issues.append(RuleIssue(
                    file=filename, line=func.line,
                    message=f"Function '{func.name}' is approximately {length} lines long (max {self.MAX_LINES}).",
                    suggestion="Break complex functions into smaller, focused functions.",
                    code_snippet=self.get_code_snippet(source_code, func.line),
                ))
        return issues


class JSVarUsageRule(BaseRule):
    rule_id = "JSCS002"
    name = "var Declaration"
    description = "var has function scope and hoisting issues — use const/let."
    severity = Severity.MINOR
    category = Category.CODE_SMELL
    languages = ["javascript"]

    PATTERN = re.compile(r'^\s*var\s+\w+')

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            if self.PATTERN.match(line):
                issues.append(RuleIssue(
                    file=filename, line=i,
                    message="Use of 'var' — prefer 'const' or 'let' for block scoping.",
                    suggestion="Replace 'var' with 'const' (if not reassigned) or 'let'.",
                    code_snippet=self.get_code_snippet(source_code, i),
                ))
        return issues


class JSTripleEqualsRule(BaseRule):
    rule_id = "JSCS003"
    name = "Loose Equality (==)"
    description = "Using == instead of === can cause unexpected type coercion."
    severity = Severity.MINOR
    category = Category.CODE_SMELL
    languages = ["javascript"]

    PATTERN = re.compile(r'(?<![=!<>])={2}(?!=)')

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('*'):
                continue
            if self.PATTERN.search(line):
                issues.append(RuleIssue(
                    file=filename, line=i,
                    message="Loose equality (==) used — may cause unexpected type coercion.",
                    suggestion="Use strict equality (===) to avoid type coercion bugs.",
                    code_snippet=self.get_code_snippet(source_code, i),
                ))
        return issues


class JSEmptyCallbackRule(BaseRule):
    rule_id = "JSCS004"
    name = "Empty Catch Block (JS)"
    description = "Empty catch blocks swallow errors silently."
    severity = Severity.MAJOR
    category = Category.CODE_SMELL
    languages = ["javascript"]

    PATTERN = re.compile(r'catch\s*\([^)]*\)\s*\{\s*\}')

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        # Check across the full source for empty catch blocks
        for match in self.PATTERN.finditer(source_code):
            line_num = source_code[:match.start()].count('\n') + 1
            issues.append(RuleIssue(
                file=filename, line=line_num,
                message="Empty catch block — errors are silently swallowed.",
                suggestion="Log the error or handle it appropriately. Never silently ignore exceptions.",
                code_snippet=self.get_code_snippet(source_code, line_num),
            ))
        return issues


class JSNoConsoleRule(BaseRule):
    rule_id = "JSCS005"
    name = "Console Statement"
    description = "console.log and similar statements should not be in production code."
    severity = Severity.INFO
    category = Category.CODE_SMELL
    languages = ["javascript"]

    PATTERN = re.compile(r'\bconsole\.(log|debug|info)\s*\(')

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('*'):
                continue
            if self.PATTERN.search(line):
                issues.append(RuleIssue(
                    file=filename, line=i,
                    message="console statement found — remove before production deployment.",
                    suggestion="Use a proper logging library (winston, pino) with configurable log levels.",
                    code_snippet=self.get_code_snippet(source_code, i),
                ))
        return issues


class JSPromiseHandlingRule(BaseRule):
    rule_id = "JSCS006"
    name = "Unhandled Promise"
    description = "Promises without .catch() or try/await can cause unhandled rejections."
    severity = Severity.MAJOR
    category = Category.CODE_SMELL
    languages = ["javascript"]

    # Detect .then() without .catch()
    THEN_NO_CATCH = re.compile(r'\.then\s*\([^)]*\)\s*(?!\.catch)')

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            if self.THEN_NO_CATCH.search(line) and '.catch' not in line:
                issues.append(RuleIssue(
                    file=filename, line=i,
                    message="Promise .then() without .catch() — unhandled rejection risk.",
                    suggestion="Add .catch() handler or use async/await with try/catch.",
                    code_snippet=self.get_code_snippet(source_code, i),
                ))
        return issues


class JSMagicNumberRule(BaseRule):
    rule_id = "JSCS007"
    name = "Magic Number"
    description = "Unexplained numeric literals reduce code readability."
    severity = Severity.INFO
    category = Category.MAINTAINABILITY
    languages = ["javascript"]

    # Match numbers > 1 that aren't in common safe positions
    PATTERN = re.compile(r'(?<![.\w])(?!0x)([2-9]\d{2,}|\d{4,})(?![\w.])')

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('*') or 'const' in line or 'PORT' in line:
                continue
            match = self.PATTERN.search(line)
            if match:
                issues.append(RuleIssue(
                    file=filename, line=i,
                    message=f"Magic number {match.group()} — use a named constant.",
                    suggestion="Extract magic numbers into named constants for readability.",
                    code_snippet=self.get_code_snippet(source_code, i),
                ))
        return issues


class JSDeepNestingRule(BaseRule):
    rule_id = "JSCS008"
    name = "Deep Nesting (JS)"
    description = "Code nested more than 4 levels deep is hard to read."
    severity = Severity.MINOR
    category = Category.CODE_SMELL
    languages = ["javascript"]

    MAX_DEPTH = 4

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        reported = set()
        depth = 0
        for i, line in enumerate(source_code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('*'):
                continue
            depth += line.count('{') - line.count('}')
            if depth > self.MAX_DEPTH and i not in reported:
                reported.add(i)
                issues.append(RuleIssue(
                    file=filename, line=i,
                    message=f"Code nested {depth} levels deep (max {self.MAX_DEPTH}).",
                    suggestion="Reduce nesting with early returns, guard clauses, or extracted functions.",
                    code_snippet=self.get_code_snippet(source_code, i),
                ))
        return issues
