"""
Taint Analysis Engine — Basic data flow tracking for security vulnerabilities.

Tracks data from sources (user input, HTTP requests, env vars) to
sinks (SQL queries, OS commands, eval, file writes) through variable assignments.
"""
import ast
from typing import List, Dict, Set, Optional
from backend.rule_engine.base import RuleIssue


# Taint sources — functions/attributes that introduce untrusted data
PYTHON_SOURCES = {
    # Flask / Django request objects
    "request.args", "request.form", "request.data", "request.json",
    "request.values", "request.files", "request.cookies", "request.headers",
    "request.GET", "request.POST", "request.body",
    # Built-in input
    "input",
    # Environment
    "os.environ", "os.getenv", "os.environ.get",
    # File reads
    "open", "read", "readline", "readlines",
    # sys
    "sys.argv", "sys.stdin",
}

# Taint sinks — functions that are dangerous with untrusted data
PYTHON_SINKS = {
    # SQL injection
    "cursor.execute": "SQL Injection",
    "execute": "SQL Injection",
    "executemany": "SQL Injection",
    "raw": "SQL Injection (Django ORM raw query)",
    # OS command injection
    "os.system": "OS Command Injection",
    "os.popen": "OS Command Injection",
    "subprocess.call": "OS Command Injection",
    "subprocess.run": "OS Command Injection",
    "subprocess.Popen": "OS Command Injection",
    # Code injection
    "eval": "Code Injection via eval()",
    "exec": "Code Injection via exec()",
    "compile": "Code Injection via compile()",
    # Deserialization
    "pickle.loads": "Unsafe Deserialization",
    "pickle.load": "Unsafe Deserialization",
    "yaml.load": "Unsafe YAML Deserialization",
    "marshal.loads": "Unsafe Deserialization",
    # Template injection
    "render_template_string": "Server-Side Template Injection",
    "Template": "Server-Side Template Injection",
    # SSRF
    "requests.get": "Potential SSRF",
    "requests.post": "Potential SSRF",
    "urllib.request.urlopen": "Potential SSRF",
    "httpx.get": "Potential SSRF",
    # File write
    "write": "Arbitrary File Write",
}


class TaintTracker:
    """
    Performs basic intra-procedural taint analysis on Python ASTs.
    
    Tracks which variables hold tainted data (from sources) and
    detects when tainted data flows into security-sensitive sinks.
    """

    def __init__(self):
        self.tainted_vars: Set[str] = set()
        self.issues: List[RuleIssue] = []

    def analyze(self, tree: ast.Module, source_code: str, filename: str) -> List[RuleIssue]:
        """
        Run taint analysis on the given AST.

        Returns a list of RuleIssue for each source-to-sink flow detected.
        """
        self.tainted_vars = set()
        self.issues = []
        self._visit(tree, source_code, filename)
        return self.issues

    def _visit(self, node: ast.AST, source_code: str, filename: str):
        """Walk the AST and track taint propagation."""
        for child in ast.walk(node):
            # Track assignments: x = request.args.get(...)
            if isinstance(child, ast.Assign):
                self._handle_assign(child, source_code, filename)
            # Track augmented assignments: x += input(...)
            elif isinstance(child, ast.AugAssign):
                if self._is_tainted_expr(child.value):
                    target_name = self._get_name(child.target)
                    if target_name:
                        self.tainted_vars.add(target_name)
            # Check function calls for sinks
            elif isinstance(child, ast.Call):
                self._handle_call(child, source_code, filename)

    def _handle_assign(self, node: ast.Assign, source_code: str, filename: str):
        """Handle an assignment statement to propagate taint."""
        is_tainted = self._is_tainted_expr(node.value)
        for target in node.targets:
            target_name = self._get_name(target)
            if target_name:
                if is_tainted:
                    self.tainted_vars.add(target_name)
                else:
                    # If re-assigned with clean data, remove taint
                    self.tainted_vars.discard(target_name)

    def _handle_call(self, node: ast.Call, source_code: str, filename: str):
        """Check if a call is a sink receiving tainted arguments."""
        func_name = self._get_call_name(node)
        if not func_name:
            return

        sink_vuln = None
        for sink_pattern, vuln_type in PYTHON_SINKS.items():
            if func_name == sink_pattern or func_name.endswith("." + sink_pattern):
                sink_vuln = vuln_type
                break

        if sink_vuln:
            # Check if any argument is tainted
            for arg in node.args:
                if self._is_tainted_expr(arg):
                    lines = source_code.splitlines()
                    line_num = getattr(node, 'lineno', 0)
                    snippet = lines[line_num - 1].strip() if 0 < line_num <= len(lines) else ""
                    self.issues.append(RuleIssue(
                        file=filename,
                        line=line_num,
                        column=getattr(node, 'col_offset', 0),
                        message=f"Tainted data flows into {func_name}() — {sink_vuln}",
                        suggestion=f"Sanitize or validate the input before passing to {func_name}().",
                        code_snippet=snippet,
                    ))
                    break
            # Also check keyword arguments
            for kw in node.keywords:
                if self._is_tainted_expr(kw.value):
                    line_num = getattr(node, 'lineno', 0)
                    self.issues.append(RuleIssue(
                        file=filename,
                        line=line_num,
                        column=getattr(node, 'col_offset', 0),
                        message=f"Tainted data flows into {func_name}() via keyword arg — {sink_vuln}",
                        suggestion=f"Sanitize or validate the input before passing to {func_name}().",
                    ))
                    break

    def _is_tainted_expr(self, node: ast.AST) -> bool:
        """Check if an expression is tainted (is a source or uses a tainted variable)."""
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        elif isinstance(node, ast.Attribute):
            full_name = self._get_attr_name(node)
            if full_name:
                # Check if it matches a known source
                for source in PYTHON_SOURCES:
                    if full_name == source or full_name.endswith(source):
                        return True
            # Check if base is tainted
            base_name = self._get_name(node.value)
            return base_name in self.tainted_vars if base_name else False
        elif isinstance(node, ast.Call):
            func_name = self._get_call_name(node)
            if func_name:
                for source in PYTHON_SOURCES:
                    if func_name == source or func_name.endswith(source):
                        return True
            # If the function itself is tainted
            if isinstance(node.func, ast.Name) and node.func.id in self.tainted_vars:
                return True
            # Check arguments to propagate taint through calls
            return any(self._is_tainted_expr(arg) for arg in node.args)
        elif isinstance(node, ast.BinOp):
            return self._is_tainted_expr(node.left) or self._is_tainted_expr(node.right)
        elif isinstance(node, ast.JoinedStr):  # f-strings
            return any(
                self._is_tainted_expr(v.value) if isinstance(v, ast.FormattedValue) else False
                for v in node.values
            )
        elif isinstance(node, ast.Subscript):
            base_name = self._get_name(node.value)
            return base_name in self.tainted_vars if base_name else False
        return False

    def _get_name(self, node: ast.AST) -> Optional[str]:
        """Get the name of a simple Name or Attribute node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_attr_name(node)
        elif isinstance(node, ast.Starred):
            return self._get_name(node.value)
        return None

    def _get_attr_name(self, node: ast.Attribute) -> Optional[str]:
        """Get dotted attribute name like 'request.args'."""
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))
        return None

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Get the name of the function being called."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return self._get_attr_name(node.func)
        return None
