"""
Type Safety Rules — Missing type annotations, Any overuse, implicit Optional misuse.
"""
import ast
from typing import List
from backend.rule_engine.base import BaseRule, RuleIssue
from backend.core.config import Severity, Category


class MissingTypeAnnotationsRule(BaseRule):
    rule_id = "TYPE001"
    name = "Missing Type Annotations"
    description = "Public functions should have type annotations on parameters and return type."
    severity = Severity.MINOR
    category = Category.MAINTAINABILITY
    languages = ["python"]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues
        for node in ast.walk(ast_tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name.startswith("_"):
                continue

            args = node.args
            all_args = args.args + args.kwonlyargs + (
                [args.vararg] if args.vararg else []
            ) + ([args.kwarg] if args.kwarg else [])

            unannotated = [
                a.arg for a in all_args
                if a.annotation is None and a.arg not in ("self", "cls")
            ]
            missing_return = node.returns is None

            if unannotated:
                issues.append(RuleIssue(
                    file=filename,
                    line=node.lineno,
                    message=f"Function '{node.name}' has unannotated parameters: {', '.join(unannotated)}.",
                    suggestion="Add type annotations: def func(x: int, y: str) -> bool:",
                    code_snippet=self.get_code_snippet(source_code, node.lineno),
                ))
            if missing_return:
                issues.append(RuleIssue(
                    file=filename,
                    line=node.lineno,
                    message=f"Function '{node.name}' is missing a return type annotation.",
                    suggestion="Add return type: def func(...) -> ReturnType: or -> None:",
                    code_snippet=self.get_code_snippet(source_code, node.lineno),
                ))
        return issues


class AnyTypeOveruseRule(BaseRule):
    rule_id = "TYPE002"
    name = "Overuse of Any Type"
    description = "Using typing.Any disables type checking — use specific types instead."
    severity = Severity.MINOR
    category = Category.MAINTAINABILITY
    languages = ["python"]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues

        def _is_any(node) -> bool:
            if isinstance(node, ast.Name) and node.id == "Any":
                return True
            if isinstance(node, ast.Attribute) and node.attr == "Any":
                return True
            return False

        for node in ast.walk(ast_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for arg in node.args.args + node.args.kwonlyargs:
                    if arg.annotation and _is_any(arg.annotation):
                        issues.append(RuleIssue(
                            file=filename,
                            line=node.lineno,
                            message=f"Parameter '{arg.arg}' in '{node.name}' annotated as Any — use a specific type.",
                            suggestion="Replace Any with a concrete type or Union of specific types.",
                            code_snippet=self.get_code_snippet(source_code, node.lineno),
                        ))
                if node.returns and _is_any(node.returns):
                    issues.append(RuleIssue(
                        file=filename,
                        line=node.lineno,
                        message=f"Return type of '{node.name}' is Any — use a specific type.",
                        suggestion="Replace Any with a concrete return type.",
                        code_snippet=self.get_code_snippet(source_code, node.lineno),
                    ))
        return issues


class ImplicitOptionalRule(BaseRule):
    rule_id = "TYPE003"
    name = "Implicit Optional Parameter"
    description = "Parameters with default=None should be annotated as Optional[T] or T | None."
    severity = Severity.MINOR
    category = Category.MAINTAINABILITY
    languages = ["python"]

    def check(self, ast_tree, source_code: str, filename: str) -> List[RuleIssue]:
        issues = []
        if ast_tree is None:
            return issues

        def _is_optional(annotation) -> bool:
            if annotation is None:
                return True  # no annotation — skip, TYPE001 covers this
            # Optional[X]
            if isinstance(annotation, ast.Subscript):
                name = ""
                if isinstance(annotation.value, ast.Name):
                    name = annotation.value.id
                elif isinstance(annotation.value, ast.Attribute):
                    name = annotation.value.attr
                if name == "Optional":
                    return True
            # X | None  (Python 3.10+)
            if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
                if isinstance(annotation.right, ast.Constant) and annotation.right.value is None:
                    return True
                if isinstance(annotation.left, ast.Constant) and annotation.left.value is None:
                    return True
            # None literal
            if isinstance(annotation, ast.Constant) and annotation.value is None:
                return True
            return False

        for node in ast.walk(ast_tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            args = node.args
            # defaults align to the end of args.args
            offset = len(args.args) - len(args.defaults)
            for i, default in enumerate(args.defaults):
                if isinstance(default, ast.Constant) and default.value is None:
                    arg = args.args[offset + i]
                    if arg.annotation is not None and not _is_optional(arg.annotation):
                        issues.append(RuleIssue(
                            file=filename,
                            line=node.lineno,
                            message=f"Parameter '{arg.arg}' defaults to None but is not annotated as Optional.",
                            suggestion=f"Change annotation to Optional[T] or T | None: {arg.arg}: Optional[YourType] = None",
                            code_snippet=self.get_code_snippet(source_code, node.lineno),
                        ))
        return issues
