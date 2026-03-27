"""
SQL Rules — Static analysis rules for .sql files.
Uses regex-based line scanning (no AST needed).
"""
import re
from typing import List
from backend.rule_engine.base import BaseRule, RuleIssue
from backend.core.config import Severity, Category, OWASP


class SQLDynamicQueryRule(BaseRule):
    rule_id = "SQL001"
    name = "Dynamic SQL Construction"
    description = "Detects EXEC/EXECUTE with string concatenation — SQL injection risk."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    owasp_category = OWASP.A03_INJECTION
    languages = ["sql"]

    _pattern = re.compile(r'\bEXEC(UTE)?\s*\(', re.IGNORECASE)

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            if self._pattern.search(line):
                issues.append(RuleIssue(
                    file=filename, line=i,
                    message="Dynamic SQL via EXEC() detected — potential SQL injection.",
                    suggestion="Use sp_executesql with parameters instead of EXEC with concatenated strings.",
                    code_snippet=self.get_code_snippet(source_code, i),
                ))
        return issues


class SQLSelectStarRule(BaseRule):
    rule_id = "SQL002"
    name = "SELECT * Usage"
    description = "SELECT * retrieves all columns, hurting performance and maintainability."
    severity = Severity.MINOR
    category = Category.PERFORMANCE
    owasp_category = None
    languages = ["sql"]

    _pattern = re.compile(r'\bSELECT\s+\*', re.IGNORECASE)

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith('--'):
                continue
            if self._pattern.search(line):
                issues.append(RuleIssue(
                    file=filename, line=i,
                    message="SELECT * used — explicitly list required columns instead.",
                    suggestion="Replace SELECT * with explicit column names to improve performance and clarity.",
                    code_snippet=self.get_code_snippet(source_code, i),
                ))
        return issues


class SQLMissingWhereRule(BaseRule):
    rule_id = "SQL003"
    name = "DELETE/UPDATE Without WHERE"
    description = "DELETE or UPDATE without a WHERE clause affects all rows."
    severity = Severity.BLOCKER
    category = Category.SECURITY
    owasp_category = OWASP.A04_INSECURE_DESIGN
    languages = ["sql"]

    _delete = re.compile(r'\bDELETE\s+FROM\s+\w+\s*;', re.IGNORECASE)
    _update = re.compile(r'\bUPDATE\s+\w+\s+SET\b(?!.*\bWHERE\b)', re.IGNORECASE | re.DOTALL)

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        lines = source_code.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('--'):
                continue
            if self._delete.search(line):
                issues.append(RuleIssue(
                    file=filename, line=i,
                    message="DELETE FROM without WHERE clause — will delete all rows.",
                    suggestion="Add a WHERE clause to limit the rows affected.",
                    code_snippet=self.get_code_snippet(source_code, i),
                ))
        # Check multi-line UPDATE blocks
        full = source_code.upper()
        for m in re.finditer(r'\bUPDATE\s+\w+\s+SET\b', full, re.IGNORECASE):
            # Find the statement end (next semicolon)
            end = full.find(';', m.end())
            stmt = full[m.start(): end + 1] if end != -1 else full[m.start():]
            if 'WHERE' not in stmt:
                line_no = source_code[:m.start()].count('\n') + 1
                issues.append(RuleIssue(
                    file=filename, line=line_no,
                    message="UPDATE without WHERE clause — will update all rows.",
                    suggestion="Add a WHERE clause to limit the rows affected.",
                    code_snippet=self.get_code_snippet(source_code, line_no),
                ))
        return issues


class SQLHardcodedCredentialsRule(BaseRule):
    rule_id = "SQL004"
    name = "Hardcoded Credentials in SQL"
    description = "Detects hardcoded passwords or connection strings in SQL files."
    severity = Severity.CRITICAL
    category = Category.SECURITY
    owasp_category = OWASP.A07_AUTH_FAILURES
    languages = ["sql"]

    _pattern = re.compile(r"(?i)(password|pwd|passwd)\s*=\s*['\"][^'\"]+['\"]")

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        for i, line in enumerate(source_code.splitlines(), 1):
            if self._pattern.search(line):
                issues.append(RuleIssue(
                    file=filename, line=i,
                    message="Hardcoded credential detected in SQL file.",
                    suggestion="Use environment variables or a secrets manager for credentials.",
                    code_snippet=self.get_code_snippet(source_code, i),
                ))
        return issues


class SQLNoTransactionRule(BaseRule):
    rule_id = "SQL005"
    name = "Missing Transaction Control"
    description = "Multiple DML statements without explicit transaction control."
    severity = Severity.MAJOR
    category = Category.MAINTAINABILITY
    owasp_category = None
    languages = ["sql"]

    _dml = re.compile(r'\b(INSERT|UPDATE|DELETE)\b', re.IGNORECASE)
    _txn = re.compile(r'\b(BEGIN|COMMIT|ROLLBACK|TRANSACTION)\b', re.IGNORECASE)

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        dml_count = len(self._dml.findall(source_code))
        has_txn = bool(self._txn.search(source_code))
        if dml_count >= 2 and not has_txn:
            issues.append(RuleIssue(
                file=filename, line=1,
                message=f"Found {dml_count} DML statements with no transaction control (BEGIN/COMMIT/ROLLBACK).",
                suggestion="Wrap multiple DML statements in a transaction to ensure atomicity.",
                code_snippet=self.get_code_snippet(source_code, 1),
            ))
        return issues
