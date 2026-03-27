"""
Python AST Parser - Parses Python source files into ASTs using the built-in ast module.
"""
import ast
from typing import Optional, Tuple


class PythonParser:
    """Parser for Python source files using the built-in ast module."""

    def parse(self, source_code: str, filename: str = "<unknown>") -> Optional[ast.Module]:
        """
        Parse Python source code into an AST.

        Args:
            source_code: The raw Python source code.
            filename: The filename for error reporting.

        Returns:
            An ast.Module node, or None if parsing fails.
        """
        try:
            tree = ast.parse(source_code, filename=filename)
            return tree
        except SyntaxError as e:
            print(f"[PythonParser] SyntaxError in {filename}: {e}")
            return None

    def get_all_nodes(self, tree: ast.Module):
        """Yield all AST nodes via depth-first traversal."""
        for node in ast.walk(tree):
            yield node

    def get_functions(self, tree: ast.Module):
        """Yield all function/method definitions."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield node

    def get_classes(self, tree: ast.Module):
        """Yield all class definitions."""
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                yield node

    def get_imports(self, tree: ast.Module):
        """Yield all import statements."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                yield node

    def get_calls(self, tree: ast.Module):
        """Yield all function call nodes."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                yield node

    def get_function_complexity(self, func_node) -> int:
        """
        Calculate cyclomatic complexity for a function node.
        Counts decision points: if, elif, for, while, except, and, or, assert, with, ternary.
        """
        complexity = 1  # Base complexity
        for node in ast.walk(func_node):
            if isinstance(node, (ast.If, ast.IfExp)):
                complexity += 1
            elif isinstance(node, ast.For):
                complexity += 1
            elif isinstance(node, ast.While):
                complexity += 1
            elif isinstance(node, ast.ExceptHandler):
                complexity += 1
            elif isinstance(node, ast.Assert):
                complexity += 1
            elif isinstance(node, ast.With):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                # Each 'and'/'or' adds a decision path
                complexity += len(node.values) - 1
        return complexity
