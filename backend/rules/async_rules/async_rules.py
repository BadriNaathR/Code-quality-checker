"""
Async Safety Rules — Blocking calls inside async functions, missing await,
asyncio anti-patterns.
"""
import ast
from typing import List
from backend.rule_engine.base import BaseRule, RuleIssue
from backend.core.config import Severity, Category


# Blocking calls that must not be used inside async functions
_BLOCKING_CALLS = {
    "time.sleep": "Use await asyncio.sleep() instead.",
    "requests.get": "Use httpx.AsyncClient or aiohttp for async HTTP requests.",
    "requests.post": "Use httpx.AsyncClient or aiohttp for async HTTP requests.",
    "requests.put": "Use httpx.AsyncClient or aiohttp for async HTTP requests.",
    "requests.delete": "Use httpx.AsyncClient or aiohttp for async HTTP requests.",
    "requests.patch": "Use httpx.AsyncClient or aiohttp for async HTTP requests.",
    "requests.request": "Use httpx.AsyncClient or aiohttp for async HTTP requests.",
    "urllib.request.urlopen": "Use httpx.AsyncClient or aiohttp for async HTTP requests.",
    "subprocess.run": "Use asyncio.create_subprocess_exec() for async subprocess calls.",
    "subprocess.call": "Use asyncio.create_subprocess_exec() for async subprocess calls.",
    "subprocess.Popen": "Use asyncio.create_subprocess_exec() for async subprocess calls.",
    "os.system": "Use asyncio.create_subprocess_shell() for async shell commands.",
    "input": "Use async input alternatives; input() blocks the event loop.",
}

# Coroutine-returning functions that are commonly forgotten to await
_COMMON_AWAITABLES = {
    "asyncio.sleep",
    "asyncio.gather",
    "asyncio.wait",
    "asyncio.wait_for",
    "asyncio.create_task",
    "asyncio.shield",
}


class BlockingCallInAsyncRule(BaseRule):
    rule_id = "ASYNC001"
    name = "Blocking Call in Async Function"
    description = "Synchronous blocking calls inside async functions stall the event loop."
    severity = Severity.CRITICAL
    category = Category.PERFORMANCE
    languages = ["python"]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues

        for node in ast.walk(ast_tree):
            if not isinstance(node, ast.AsyncFunctionDef):
                continue
            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue
                name = self._get_call_name(child)
                if name in _BLOCKING_CALLS:
                    issues.append(RuleIssue(
                        file=filename,
                        line=child.lineno,
                        message=f"Blocking call '{name}()' inside async function '{node.name}' — stalls the event loop.",
                        suggestion=_BLOCKING_CALLS[name],
                        code_snippet=self.get_code_snippet(source_code, child.lineno),
                    ))
        return issues

    def _get_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            cur = node.func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        return ""


class MissingAwaitRule(BaseRule):
    rule_id = "ASYNC002"
    name = "Missing Await on Coroutine"
    description = "Calling a coroutine without await creates a coroutine object that is never executed."
    severity = Severity.CRITICAL
    category = Category.CODE_SMELL
    languages = ["python"]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues

        for node in ast.walk(ast_tree):
            if not isinstance(node, ast.AsyncFunctionDef):
                continue
            for child in ast.walk(node):
                # A bare Call statement (not awaited, not assigned)
                if not isinstance(child, ast.Expr):
                    continue
                if not isinstance(child.value, ast.Call):
                    continue
                call = child.value
                name = self._get_call_name(call)
                if name in _COMMON_AWAITABLES:
                    issues.append(RuleIssue(
                        file=filename,
                        line=child.lineno,
                        message=f"'{name}()' called without await — coroutine is never executed.",
                        suggestion=f"Add await: await {name}(...)",
                        code_snippet=self.get_code_snippet(source_code, child.lineno),
                    ))
        return issues

    def _get_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            cur = node.func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        return ""


class AsyncWithoutAsyncContextRule(BaseRule):
    rule_id = "ASYNC003"
    name = "Sync open() in Async Function"
    description = "Using synchronous open() for file I/O inside async functions blocks the event loop."
    severity = Severity.MAJOR
    category = Category.PERFORMANCE
    languages = ["python"]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues

        for node in ast.walk(ast_tree):
            if not isinstance(node, ast.AsyncFunctionDef):
                continue
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    if isinstance(child.func, ast.Name) and child.func.id == "open":
                        issues.append(RuleIssue(
                            file=filename,
                            line=child.lineno,
                            message=f"Synchronous open() inside async function '{node.name}' blocks the event loop.",
                            suggestion="Use aiofiles: async with aiofiles.open(...) as f:",
                            code_snippet=self.get_code_snippet(source_code, child.lineno),
                        ))
        return issues


class AsyncSleepZeroRule(BaseRule):
    rule_id = "ASYNC004"
    name = "asyncio.sleep(0) Misuse"
    description = "asyncio.sleep(0) is a yield point — using it in a tight loop is a code smell."
    severity = Severity.MINOR
    category = Category.PERFORMANCE
    languages = ["python"]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues

        for node in ast.walk(ast_tree):
            if not isinstance(node, (ast.For, ast.While)):
                continue
            for child in ast.walk(node):
                if not isinstance(child, ast.Await):
                    continue
                call = child.value
                if not isinstance(call, ast.Call):
                    continue
                name = ""
                if isinstance(call.func, ast.Attribute):
                    name = f"{getattr(call.func.value, 'id', '')}.{call.func.attr}"
                if name == "asyncio.sleep" and call.args:
                    arg = call.args[0]
                    if isinstance(arg, ast.Constant) and arg.value == 0:
                        issues.append(RuleIssue(
                            file=filename,
                            line=child.lineno,
                            message="asyncio.sleep(0) in a loop — consider a proper async queue or event instead.",
                            suggestion="Use asyncio.Queue or asyncio.Event for producer/consumer patterns.",
                            code_snippet=self.get_code_snippet(source_code, child.lineno),
                        ))
        return issues
