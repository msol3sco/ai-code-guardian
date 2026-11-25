import ast
from dataclasses import dataclass

REQUEST_METHODS = {"delete", "get", "head", "options", "patch", "post", "put", "request"}
SESSION_METHODS = REQUEST_METHODS | {"send"}
FACTORIES = {"requests.Session", "requests.session", "requests.sessions.Session", "requests.sessions.session"}
REQUEST_MODULES = {"requests", "requests.sessions"}
SESSION = "<requests session>"


def disabled_verify_line(call: ast.Call) -> int | None:
    for keyword in call.keywords:
        if keyword.arg == "verify" and isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
            return keyword.value.lineno
    return None


@dataclass(frozen=True)
class Binding:
    position: tuple[int, int]
    value: ast.expr | str | None


class SessionScope(ast.NodeVisitor):
    """Resolve Requests names only when a lexical scope has one known binding."""

    def __init__(self, parent: "SessionScope | None" = None, *, in_class: bool = False):
        self.parent = parent
        self.in_class = in_class
        self.bindings: dict[str, list[Binding]] = {}
        self.candidates: list[tuple[ast.expr, int, int]] = []
        self.children: list[SessionScope] = []

    def bind(self, name: str, node: ast.expr | ast.stmt | ast.arg, value: ast.expr | str | None = None) -> None:
        position = (node.end_lineno or node.lineno, node.end_col_offset or node.col_offset)
        self.bindings.setdefault(name, []).append(Binding(position, value))

    def resolve(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            bindings = self.bindings.get(node.id)
            if bindings is None:
                return self.parent.resolve(node) if self.parent else ""
            if len(bindings) == 1 and bindings[0].position <= (node.lineno, node.col_offset):
                value = bindings[0].value
                if isinstance(value, ast.expr):
                    return self.resolve(value)
                return value or ""
        elif isinstance(node, ast.Attribute):
            owner = self.resolve(node.value)
            if owner in REQUEST_MODULES:
                return f"{owner}.{node.attr}"
        elif isinstance(node, ast.Call) and self.resolve(node.func) in FACTORIES:
            return SESSION
        return ""

    def visit_Import(self, node: ast.Import) -> None:
        for item in node.names:
            name = item.name if item.asname else item.name.split(".")[0]
            self.bind(item.asname or name, node, name if name in REQUEST_MODULES else None)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for item in node.names:
            symbol = f"{node.module}.{item.name}"
            known = symbol if not node.level and symbol in FACTORIES | REQUEST_MODULES else None
            self.bind(item.asname or item.name, node, known)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bind(node.id, node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute) and node.func.attr in SESSION_METHODS:
            line = disabled_verify_line(node)
            if line is not None:
                self.candidates.append((node.func.value, line, node.func.lineno))
        self.generic_visit(node)

    def assign(self, target: ast.expr, value: ast.expr | None) -> None:
        if isinstance(target, ast.Name):
            self.bind(target.id, value if value is not None else target, value)
        else:
            self.visit(target)
            if (
                isinstance(target, ast.Attribute) and target.attr == "verify"
                and isinstance(value, ast.Constant) and value.value is False
            ):
                self.candidates.append((target.value, value.lineno, target.lineno))

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for target in node.targets:
            self.assign(target, node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
        self.assign(node.target, node.value)

    def visit_withitem(self, node: ast.withitem) -> None:
        self.visit(node.context_expr)
        if node.optional_vars is not None:
            self.assign(node.optional_vars, node.context_expr)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self.mask(node.name)
        self.generic_visit(node)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        self.mask(node.name)
        self.generic_visit(node)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        self.mask(node.name)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        self.mask(node.rest)
        self.generic_visit(node)

    def mask(self, name: str | None) -> None:
        if name is not None:
            self.bindings.setdefault(name, []).append(Binding((0, 0), None))

    def child(self, *, in_class: bool = False) -> "SessionScope":
        parent = self.parent if self.in_class else self
        scope = SessionScope(parent, in_class=in_class)
        self.children.append(scope)
        return scope

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.mask(node.name)
        scope = self.child()
        for argument in ast.iter_child_nodes(node.args):
            if isinstance(argument, ast.arg):
                scope.mask(argument.arg)
        for statement in node.body:
            scope.visit(statement)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.mask(node.name)
        scope = self.child(in_class=True)
        for statement in node.body:
            scope.visit(statement)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        scope = self.child()
        for argument in ast.iter_child_nodes(node.args):
            if isinstance(argument, ast.arg):
                scope.mask(argument.arg)
        scope.visit(node.body)

    def visit_ListComp(self, node: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp) -> None:
        self.child().generic_visit(node)

    visit_SetComp = visit_DictComp = visit_GeneratorExp = visit_ListComp

    def findings(self) -> list[tuple[int, int]]:
        found = [(line, fallback) for receiver, line, fallback in self.candidates if self.resolve(receiver) == SESSION]
        for child in self.children:
            found.extend(child.findings())
        return found


def session_tls_findings(tree: ast.AST) -> list[tuple[int, int]]:
    scope = SessionScope()
    scope.visit(tree)
    return scope.findings()
