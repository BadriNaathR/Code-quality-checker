"""
Metrics Calculator — Computes code quality metrics.

Metrics:
    - Cyclomatic Complexity (per function and file average)
    - Lines of Code (total, code, comment, blank)
    - Function Length
    - Class Complexity
    - Maintainability Index
    - Duplication Detection (basic)
"""
import ast
import math
import re
from typing import List, Dict, Any, Optional
from collections import Counter
from backend.parsers.python_parser import PythonParser


class MetricsCalculator:
    """Calculates code quality metrics for Python source files."""

    def __init__(self):
        self.parser = PythonParser()

    def calculate_all(self, source_code: str, filename: str) -> List[Dict[str, Any]]:
        """Calculate all metrics for a source file. Returns a list of metric dicts."""
        metrics = []

        # LOC metrics
        loc = self.calculate_loc(source_code)
        metrics.append({"file": filename, "metric_type": "loc", "metric_name": "Total Lines", "value": loc["total"], "details": str(loc)})
        metrics.append({"file": filename, "metric_type": "loc", "metric_name": "Code Lines", "value": loc["code"]})
        metrics.append({"file": filename, "metric_type": "loc", "metric_name": "Comment Lines", "value": loc["comment"]})
        metrics.append({"file": filename, "metric_type": "loc", "metric_name": "Blank Lines", "value": loc["blank"]})

        # Parse AST for complexity metrics
        tree = self.parser.parse(source_code, filename)
        if tree is None:
            return metrics

        # Cyclomatic complexity per function
        func_complexities = self.calculate_cyclomatic_complexity(tree)
        for fc in func_complexities:
            metrics.append({
                "file": filename,
                "metric_type": "cyclomatic_complexity",
                "metric_name": f"CC: {fc['name']}",
                "value": fc["complexity"],
                "details": f"line {fc['line']}"
            })

        # Average complexity
        if func_complexities:
            avg_cc = sum(fc["complexity"] for fc in func_complexities) / len(func_complexities)
            metrics.append({"file": filename, "metric_type": "avg_complexity", "metric_name": "Average Cyclomatic Complexity", "value": round(avg_cc, 2)})

        # Function lengths
        func_lengths = self.calculate_function_lengths(tree, source_code)
        for fl in func_lengths:
            metrics.append({
                "file": filename,
                "metric_type": "function_length",
                "metric_name": f"Length: {fl['name']}",
                "value": fl["length"],
                "details": f"line {fl['line']}"
            })

        # Maintainability index
        mi = self.calculate_maintainability_index(source_code, tree)
        metrics.append({"file": filename, "metric_type": "maintainability_index", "metric_name": "Maintainability Index", "value": round(mi, 2)})

        return metrics

    def calculate_loc(self, source_code: str) -> Dict[str, int]:
        """Calculate lines of code metrics."""
        lines = source_code.splitlines()
        total = len(lines)
        blank = sum(1 for line in lines if not line.strip())
        comment = sum(1 for line in lines if line.strip().startswith('#'))
        code = total - blank - comment
        return {"total": total, "code": code, "comment": comment, "blank": blank}

    def calculate_cyclomatic_complexity(self, tree: ast.Module) -> List[Dict[str, Any]]:
        """Calculate cyclomatic complexity per function."""
        results = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                cc = self.parser.get_function_complexity(node)
                results.append({
                    "name": node.name,
                    "line": node.lineno,
                    "complexity": cc,
                })
        return results

    def calculate_function_lengths(self, tree: ast.Module, source_code: str) -> List[Dict[str, Any]]:
        """Calculate the number of lines in each function."""
        results = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end_line = getattr(node, 'end_lineno', node.lineno)
                length = end_line - node.lineno + 1
                results.append({
                    "name": node.name,
                    "line": node.lineno,
                    "length": length,
                })
        return results

    def calculate_maintainability_index(self, source_code: str, tree: ast.Module) -> float:
        """
        Compute Maintainability Index (MI) using the SEI formula:
        MI = 171 - 5.2 * ln(V) - 0.23 * G - 16.2 * ln(LOC)
        where V = Halstead Volume, G = avg cyclomatic complexity, LOC = lines of code.
        Clamped to [0, 100].
        """
        loc_data = self.calculate_loc(source_code)
        loc = max(loc_data["code"], 1)

        # Halstead Volume (simplified approximation)
        volume = self._halstead_volume(source_code)

        # Average cyclomatic complexity
        complexities = self.calculate_cyclomatic_complexity(tree)
        avg_cc = (sum(c["complexity"] for c in complexities) / len(complexities)) if complexities else 1

        try:
            mi = 171 - 5.2 * math.log(max(volume, 1)) - 0.23 * avg_cc - 16.2 * math.log(loc)
        except ValueError:
            mi = 0

        # Clamp to 0–100
        return max(0.0, min(100.0, mi))

    def _halstead_volume(self, source_code: str) -> float:
        """Approximate Halstead Volume from token counts."""
        # Split on whitespace and operators to get tokens
        tokens = re.findall(r'[a-zA-Z_]\w*|[^\s\w]', source_code)
        if not tokens:
            return 1

        counter = Counter(tokens)
        n1 = len([t for t in counter if not t.isalnum()])  # operator types
        n2 = len([t for t in counter if t.isalnum()])  # operand types
        N1 = sum(counter[t] for t in counter if not t.isalnum())
        N2 = sum(counter[t] for t in counter if t.isalnum())

        N = N1 + N2
        n = max(n1 + n2, 1)
        try:
            volume = N * math.log2(n)
        except ValueError:
            volume = 1
        return max(volume, 1)

    def detect_duplicates(self, files_content: Dict[str, str], min_lines: int = 6) -> List[Dict[str, Any]]:
        """
        Basic duplication detection. Finds blocks of code duplicated across files.
        Returns a list of duplicate groups.
        """
        # Build a map of normalized line sequences to file locations
        block_map: Dict[str, List[Dict]] = {}

        for filepath, content in files_content.items():
            lines = content.splitlines()
            for i in range(len(lines) - min_lines + 1):
                block = "\n".join(line.strip() for line in lines[i:i + min_lines])
                # Skip blocks that are all blank/comments
                non_empty = [l for l in lines[i:i + min_lines] if l.strip() and not l.strip().startswith('#')]
                if len(non_empty) < min_lines // 2:
                    continue
                if block not in block_map:
                    block_map[block] = []
                block_map[block].append({"file": filepath, "start_line": i + 1, "end_line": i + min_lines})

        # Filter to only duplicated blocks
        duplicates = []
        for block, locations in block_map.items():
            if len(locations) > 1:
                duplicates.append({
                    "block_preview": block[:200],
                    "occurrences": len(locations),
                    "locations": locations,
                })

        return duplicates
