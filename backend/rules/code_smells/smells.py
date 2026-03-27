"""
Code Smell Rules — Detect code quality issues and anti-patterns in Python code.
"""
import ast
from typing import List
from backend.rule_engine.base import BaseRule, RuleIssue
from backend.core.config import Severity, Category


class TooLongFunctionRule(BaseRule):
    rule_id = "CS001"
    name = "Function Too Long"
    description = "Functions should not exceed 50 lines."
    severity = Severity.MINOR
    category = Category.CODE_SMELL
    languages = ["python"]

    MAX_LINES = 50

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues
        for node in ast.walk(ast_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end_line = getattr(node, 'end_lineno', node.lineno)
                length = end_line - node.lineno + 1
                if length > self.MAX_LINES:
                    issues.append(RuleIssue(
                        file=filename, line=node.lineno,
                        message=f"Function '{node.name}' is {length} lines long (max {self.MAX_LINES}).",
                        suggestion="Break complex functions into smaller, focused functions.",
                        code_snippet=self.get_code_snippet(source_code, node.lineno),
                    ))
        return issues


class TooManyParametersRule(BaseRule):
    rule_id = "CS002"
    name = "Too Many Parameters"
    description = "Functions should not have more than 5 parameters."
    severity = Severity.MINOR
    category = Category.CODE_SMELL
    languages = ["python"]

    MAX_PARAMS = 5

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues
        for node in ast.walk(ast_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                params = node.args
                count = len(params.args) + len(params.kwonlyargs)
                # Exclude 'self' and 'cls'
                if params.args and params.args[0].arg in ('self', 'cls'):
                    count -= 1
                if count > self.MAX_PARAMS:
                    issues.append(RuleIssue(
                        file=filename, line=node.lineno,
                        message=f"Function '{node.name}' has {count} parameters (max {self.MAX_PARAMS}).",
                        suggestion="Use a data class or dictionary to group related parameters.",
                        code_snippet=self.get_code_snippet(source_code, node.lineno),
                    ))
        return issues


class HighComplexityRule(BaseRule):
    rule_id = "CS003"
    name = "High Cyclomatic Complexity"
    description = "Functions with cyclomatic complexity > 10 are hard to test and maintain."
    severity = Severity.MAJOR
    category = Category.COMPLEXITY
    languages = ["python"]

    MAX_COMPLEXITY = 10

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues
        from backend.parsers.python_parser import PythonParser
        parser = PythonParser()
        for node in ast.walk(ast_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                cc = parser.get_function_complexity(node)
                if cc > self.MAX_COMPLEXITY:
                    issues.append(RuleIssue(
                        file=filename, line=node.lineno,
                        message=f"Function '{node.name}' has cyclomatic complexity {cc} (max {self.MAX_COMPLEXITY}).",
                        suggestion="Simplify the function by extracting conditions into helper functions or using early returns.",
                        code_snippet=self.get_code_snippet(source_code, node.lineno),
                    ))
        return issues


class DeepNestingRule(BaseRule):
    rule_id = "CS004"
    name = "Deep Nesting"
    description = "Code blocks nested more than 4 levels deep are hard to read."
    severity = Severity.MINOR
    category = Category.CODE_SMELL
    languages = ["python"]

    MAX_DEPTH = 4

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues

        reported_lines = set()

        def walk_depth(node, depth=0):
            if isinstance(node, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                depth += 1
                if depth > self.MAX_DEPTH and node.lineno not in reported_lines:
                    reported_lines.add(node.lineno)
                    issues.append(RuleIssue(
                        file=filename, line=node.lineno,
                        message=f"Code is nested {depth} levels deep (max {self.MAX_DEPTH}).",
                        suggestion="Reduce nesting with early returns, guard clauses, or by extracting inner blocks to functions.",
                        code_snippet=self.get_code_snippet(source_code, node.lineno),
                    ))
            for child in ast.iter_child_nodes(node):
                walk_depth(child, depth)

        walk_depth(ast_tree)
        return issues


class UnusedImportRule(BaseRule):
    rule_id = "CS005"
    name = "Unused Import"
    description = "Detects imports that are not used in the module."
    severity = Severity.INFO
    category = Category.CODE_SMELL
    languages = ["python"]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues

        imported_names = {}  # name -> lineno
        used_names = set()

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name
                    imported_names[name] = node.lineno
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    name = alias.asname or alias.name
                    imported_names[name] = node.lineno
            elif isinstance(node, ast.Name):
                used_names.add(node.id)
            elif isinstance(node, ast.Attribute):
                # Track first part of dotted access
                current = node
                while isinstance(current, ast.Attribute):
                    current = current.value
                if isinstance(current, ast.Name):
                    used_names.add(current.id)

        for name, lineno in imported_names.items():
            base_name = name.split('.')[0]
            if base_name not in used_names and name not in used_names:
                issues.append(RuleIssue(
                    file=filename, line=lineno,
                    message=f"Import '{name}' appears to be unused.",
                    suggestion="Remove unused imports to keep the code clean.",
                    code_snippet=self.get_code_snippet(source_code, lineno),
                ))
        return issues


class GlobalVariableRule(BaseRule):
    rule_id = "CS006"
    name = "Global Variable Usage"
    description = "Detects use of global variables."
    severity = Severity.MINOR
    category = Category.CODE_SMELL
    languages = ["python"]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Global):
                issues.append(RuleIssue(
                    file=filename, line=node.lineno,
                    message=f"Global variable(s) used: {', '.join(node.names)}",
                    suggestion="Avoid global state. Pass variables as function parameters or use class attributes.",
                    code_snippet=self.get_code_snippet(source_code, node.lineno),
                ))
        return issues


class EmptyExceptRule(BaseRule):
    rule_id = "CS007"
    name = "Bare/Empty Except"
    description = "Detects bare except: blocks that catch all exceptions."
    severity = Severity.MAJOR
    category = Category.CODE_SMELL
    languages = ["python"]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues
        for node in ast.walk(ast_tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                issues.append(RuleIssue(
                    file=filename, line=node.lineno,
                    message="Bare except block catches all exceptions, including SystemExit and KeyboardInterrupt.",
                    suggestion="Catch specific exceptions: except ValueError, except Exception.",
                    code_snippet=self.get_code_snippet(source_code, node.lineno),
                ))
        return issues
