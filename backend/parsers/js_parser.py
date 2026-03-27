"""
JavaScript Parser - Basic regex and pattern-based analysis for JS/TS files.
For a production system, tree-sitter or esprima would be used.
This provides a lightweight approach that covers core security and quality patterns.
"""
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class JSNode:
    """Lightweight representation of a JS code element."""
    type: str
    name: str
    line: int
    end_line: int
    body: str


class JavaScriptParser:
    """
    Lightweight JavaScript/TypeScript parser using regex patterns.
    Provides function extraction, call detection, and basic structure analysis.
    """

    def parse(self, source_code: str, filename: str = "<unknown>") -> Dict[str, Any]:
        """
        Parse JavaScript source code into a lightweight structure.

        Returns a dict with functions, classes, imports, calls, and raw lines.
        """
        lines = source_code.splitlines()
        result = {
            "filename": filename,
            "source": source_code,
            "lines": lines,
            "functions": self._extract_functions(source_code, lines),
            "classes": self._extract_classes(source_code, lines),
            "imports": self._extract_imports(lines),
            "calls": self._extract_calls(source_code, lines),
            "variables": self._extract_variables(lines),
        }
        return result

    def _extract_functions(self, source: str, lines: List[str]) -> List[JSNode]:
        """Extract function definitions."""
        functions = []
        # Match: function name(...) { / const name = (...) => / async function name(...)
        patterns = [
            r'(?:async\s+)?function\s+(\w+)\s*\(',
            r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(?.*?\)?\s*=>',
            r'(\w+)\s*:\s*(?:async\s+)?function\s*\(',
        ]
        for i, line in enumerate(lines):
            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    functions.append(JSNode(
                        type="function",
                        name=match.group(1),
                        line=i + 1,
                        end_line=i + 1,
                        body=line.strip(),
                    ))
                    break
        return functions

    def _extract_classes(self, source: str, lines: List[str]) -> List[JSNode]:
        """Extract class definitions."""
        classes = []
        pattern = r'class\s+(\w+)'
        for i, line in enumerate(lines):
            match = re.search(pattern, line)
            if match:
                classes.append(JSNode(
                    type="class",
                    name=match.group(1),
                    line=i + 1,
                    end_line=i + 1,
                    body=line.strip(),
                ))
        return classes

    def _extract_imports(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Extract import statements."""
        imports = []
        for i, line in enumerate(lines):
            if re.match(r'\s*(import|require)\b', line):
                imports.append({"line": i + 1, "statement": line.strip()})
        return imports

    def _extract_calls(self, source: str, lines: List[str]) -> List[Dict[str, Any]]:
        """Extract function calls."""
        calls = []
        pattern = r'(\w+(?:\.\w+)*)\s*\('
        for i, line in enumerate(lines):
            for match in re.finditer(pattern, line):
                name = match.group(1)
                # Skip keywords
                if name not in ('if', 'for', 'while', 'switch', 'catch', 'function', 'return', 'class'):
                    calls.append({"name": name, "line": i + 1})
        return calls

    def _extract_variables(self, lines: List[str]) -> List[Dict[str, Any]]:
        """Extract variable declarations."""
        variables = []
        pattern = r'(?:const|let|var)\s+(\w+)\s*='
        for i, line in enumerate(lines):
            match = re.search(pattern, line)
            if match:
                variables.append({"name": match.group(1), "line": i + 1})
        return variables
