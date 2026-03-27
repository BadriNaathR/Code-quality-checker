"""
JavaScript Metrics Calculator — Computes code quality metrics for JS/TS files.
"""
import re
from typing import List, Dict, Any


class JSMetricsCalculator:
    """Calculates code quality metrics for JavaScript/TypeScript source files."""

    def calculate_all(self, source_code: str, filename: str) -> List[Dict[str, Any]]:
        """Calculate all metrics for a JS/TS source file."""
        metrics = []

        loc = self.calculate_loc(source_code)
        metrics.append({"file": filename, "metric_type": "loc", "metric_name": "Total Lines", "value": loc["total"], "details": str(loc)})
        metrics.append({"file": filename, "metric_type": "loc", "metric_name": "Code Lines", "value": loc["code"]})
        metrics.append({"file": filename, "metric_type": "loc", "metric_name": "Comment Lines", "value": loc["comment"]})
        metrics.append({"file": filename, "metric_type": "loc", "metric_name": "Blank Lines", "value": loc["blank"]})

        functions = self._extract_functions_with_bounds(source_code)
        for func in functions:
            cc = self._estimate_complexity(func["body"])
            metrics.append({
                "file": filename,
                "metric_type": "cyclomatic_complexity",
                "metric_name": f"CC: {func['name']}",
                "value": cc,
                "details": f"line {func['line']}",
            })
            metrics.append({
                "file": filename,
                "metric_type": "function_length",
                "metric_name": f"Length: {func['name']}",
                "value": func["length"],
                "details": f"line {func['line']}",
            })

        if functions:
            avg_cc = sum(self._estimate_complexity(f["body"]) for f in functions) / len(functions)
            metrics.append({"file": filename, "metric_type": "avg_complexity", "metric_name": "Average Cyclomatic Complexity", "value": round(avg_cc, 2)})

        return metrics

    def calculate_loc(self, source_code: str) -> Dict[str, int]:
        lines = source_code.splitlines()
        total = len(lines)
        blank = sum(1 for l in lines if not l.strip())
        comment = sum(1 for l in lines if l.strip().startswith('//') or l.strip().startswith('*') or l.strip().startswith('/*'))
        code = total - blank - comment
        return {"total": total, "code": code, "comment": comment, "blank": blank}

    def _extract_functions_with_bounds(self, source_code: str) -> List[Dict]:
        """Extract functions with their line numbers and body text."""
        functions = []
        lines = source_code.splitlines()

        func_patterns = [
            re.compile(r'(?:async\s+)?function\s+(\w+)\s*\('),
            re.compile(r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>'),
            re.compile(r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function'),
            re.compile(r'(\w+)\s*\([^)]*\)\s*\{'),  # method shorthand
        ]

        for i, line in enumerate(lines):
            for pattern in func_patterns:
                match = pattern.search(line)
                if match:
                    name = match.group(1)
                    if name in ('if', 'for', 'while', 'switch', 'catch', 'class'):
                        continue
                    # Extract body by brace counting
                    body_lines = []
                    depth = 0
                    started = False
                    for j in range(i, min(i + 200, len(lines))):
                        body_lines.append(lines[j])
                        depth += lines[j].count('{') - lines[j].count('}')
                        if depth > 0:
                            started = True
                        if started and depth <= 0:
                            break
                    functions.append({
                        "name": name,
                        "line": i + 1,
                        "length": len(body_lines),
                        "body": "\n".join(body_lines),
                    })
                    break

        return functions

    def _estimate_complexity(self, body: str) -> int:
        """Estimate cyclomatic complexity from JS function body."""
        complexity = 1
        decision_patterns = [
            r'\bif\s*\(',
            r'\belse\s+if\s*\(',
            r'\bfor\s*\(',
            r'\bwhile\s*\(',
            r'\bcase\s+',
            r'\bcatch\s*\(',
            r'\?\s*[^:]+\s*:',  # ternary
            r'&&',
            r'\|\|',
        ]
        for pattern in decision_patterns:
            complexity += len(re.findall(pattern, body))
        return complexity
