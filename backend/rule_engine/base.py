"""
Base class for all analysis rules.

Every rule must subclass BaseRule and implement the check() method.
Rules are automatically discovered and registered by the rule engine.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class RuleIssue:
    """Represents a single issue found by a rule."""
    file: str
    line: int
    column: int = 0
    end_line: Optional[int] = None
    message: str = ""
    suggestion: str = ""
    code_snippet: str = ""


class BaseRule(ABC):
    """Abstract base class for all pluggable rules."""

    rule_id: str = "UNKNOWN"
    name: str = "Unknown Rule"
    description: str = ""
    severity: str = "INFO"
    category: str = "CODE_SMELL"
    owasp_category: Optional[str] = None
    languages: List[str] = ["python"]  # which languages this rule applies to

    @abstractmethod
    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        """
        Analyze the AST tree and/or source code for issues.

        Args:
            ast_tree: The parsed AST (type depends on language).
            source_code: The raw source code string.
            filename: The path to the file being analyzed.

        Returns:
            A list of RuleIssue objects for any problems found.
        """
        pass

    def get_code_snippet(self, source_code: str, line: int, context: int = 2) -> str:
        """Extract a code snippet around the given line number."""
        lines = source_code.splitlines()
        start = max(0, line - context - 1)
        end = min(len(lines), line + context)
        snippet_lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line - 1 else "    "
            snippet_lines.append(f"{prefix}{i + 1}: {lines[i]}")
        return "\n".join(snippet_lines)
