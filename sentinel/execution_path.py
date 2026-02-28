"""Execution Path Analysis — trace if vulnerable code is reachable.

ALL analysis is LOCAL. No source code is ever sent externally.
Only sanitized metadata (function names, import names, call edges) may be
sent to Claude for interpretation, with explicit audit logging.
"""

from __future__ import annotations

import ast
import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Verdicts ───────────────────────────────────────────────────────────────

REACHABLE = "REACHABLE"
NOT_REACHABLE = "NOT_REACHABLE"
IMPORTED_ONLY = "IMPORTED_ONLY"
INCONCLUSIVE = "INCONCLUSIVE"

# ── Data models ────────────────────────────────────────────────────────────


@dataclass
class ImportInfo:
    """An import statement found in source code."""
    module: str          # e.g., "jinja2.utils"
    names: list[str]     # e.g., ["urlize"] or ["*"]
    file_path: str
    line: int
    is_from_import: bool = False


@dataclass
class FunctionDef:
    """A function definition in the codebase."""
    name: str
    qualified_name: str  # module.class.func
    file_path: str
    line: int
    calls: list[str] = field(default_factory=list)  # qualified names of called functions
    is_entry_point: bool = False


@dataclass
class CallEdge:
    """An edge in the call graph."""
    caller: str       # qualified name
    callee: str       # qualified name
    file_path: str
    line: int


@dataclass
class CallChain:
    """A chain from entry point to vulnerable function."""
    steps: list[tuple[str, str, int]]  # (qualified_name, file_path, line)

    def __str__(self) -> str:
        return " → ".join(
            f"{name} ({os.path.basename(fp)}:{ln})" for name, fp, ln in self.steps
        )


@dataclass
class ExecutionPathResult:
    """Result of execution path analysis."""
    verdict: str  # REACHABLE, NOT_REACHABLE, IMPORTED_ONLY, INCONCLUSIVE
    cve_id: str
    target_package: str
    vulnerable_functions: list[str]
    call_chains: list[CallChain] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    imports_found: list[ImportInfo] = field(default_factory=list)
    has_dynamic_dispatch: bool = False
    claude_interpretation: str | None = None
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "cve_id": self.cve_id,
            "target_package": self.target_package,
            "vulnerable_functions": self.vulnerable_functions,
            "call_chains": [str(c) for c in self.call_chains],
            "entry_points": self.entry_points,
            "imports_count": len(self.imports_found),
            "has_dynamic_dispatch": self.has_dynamic_dispatch,
            "claude_interpretation": self.claude_interpretation,
            "details": self.details,
        }


# ── Sanitized context for Claude ──────────────────────────────────────────

# Patterns that look like source code
_SOURCE_CODE_KEYWORDS = re.compile(
    r"^\s*(def |class |if |for |while |return |import |from |try:|except |with |raise |yield |async |await )",
    re.MULTILINE,
)
_SOURCE_CODE_PATTERNS = [
    re.compile(r"[{};]\s*$", re.MULTILINE),  # code-like line endings (JS/Go/Java)
    re.compile(r"^\s*(function |const |let |var |=>)", re.MULTILINE),  # JS
    re.compile(r"^\s*(func |package |type \w+ struct)", re.MULTILINE),  # Go
    re.compile(r"^\s*(public |private |protected |static )", re.MULTILINE),  # Java
    re.compile(r"=\s*(True|False|None|\d+|['\"])", re.MULTILINE),  # assignments
    re.compile(r"\.\w+\(", re.MULTILINE),  # method calls like os.system(
    re.compile(r"^\s*(elif |else:)", re.MULTILINE),  # Python control flow
]


def contains_source_code(text: str) -> bool:
    """Check if text contains source code patterns.

    This is a heuristic — it catches common code patterns to prevent
    accidental leakage. Returns True if code-like content detected.
    ERRS ON THE SIDE OF CAUTION — better to block clean text than leak code.
    """
    if not text or len(text) < 10:
        return False

    # Count Python-style keyword lines: if 2+ keyword matches, it's likely code
    keyword_matches = _SOURCE_CODE_KEYWORDS.findall(text)
    if len(keyword_matches) >= 2:
        return True

    # For other languages: if 1+ pattern groups match AND any keyword, likely code
    pattern_matches = sum(1 for pat in _SOURCE_CODE_PATTERNS if pat.search(text))
    if pattern_matches >= 2:
        return True
    if pattern_matches >= 1 and len(keyword_matches) >= 1:
        return True

    return False


class SanitizedContext:
    """Context that can be sent to Claude — guaranteed no source code.

    Only contains: file names, function names, import names, line numbers,
    call graph edges, package metadata.
    """

    def __init__(self) -> None:
        self.package_name: str = ""
        self.cve_id: str = ""
        self.cve_description: str = ""
        self.function_names: list[str] = []
        self.import_names: list[str] = []
        self.call_edges: list[dict[str, str]] = []  # {caller, callee, file, line}
        self.entry_points: list[str] = []
        self.file_names: list[str] = []
        self.vulnerable_functions: list[str] = []

    def to_prompt_text(self) -> str:
        """Convert to text suitable for Claude prompt. Asserts no source code."""
        text = self._build_text()
        assert not contains_source_code(text), (
            "SECURITY VIOLATION: SanitizedContext contains source code! "
            "This must never happen."
        )
        return text

    def _build_text(self) -> str:
        lines = [
            f"Package: {self.package_name}",
            f"CVE: {self.cve_id}",
            f"CVE Description: {self.cve_description}",
            "",
            f"Vulnerable functions: {', '.join(self.vulnerable_functions)}",
            "",
            f"Entry points: {', '.join(self.entry_points)}",
            "",
            "Call graph edges:",
        ]
        for edge in self.call_edges:
            lines.append(f"  {edge['caller']} -> {edge['callee']} ({edge.get('file', '')}:{edge.get('line', '')})")
        lines.append("")
        lines.append(f"Files analyzed: {', '.join(self.file_names)}")
        lines.append(f"Imports of target package: {', '.join(self.import_names)}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "cve_id": self.cve_id,
            "cve_description": self.cve_description,
            "function_names": self.function_names,
            "import_names": self.import_names,
            "call_edges": self.call_edges,
            "entry_points": self.entry_points,
            "file_names": self.file_names,
            "vulnerable_functions": self.vulnerable_functions,
        }


# ── Audit logging ─────────────────────────────────────────────────────────

_AUDIT_LOG_PATH = Path.home() / ".sentinel" / "audit.log"


def audit_log(what_was_sent: dict[str, Any]) -> None:
    """Log exactly what was sent to Claude for audit purposes."""
    _AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    import datetime
    entry = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "action": "claude_api_call",
        "data_sent": what_was_sent,
    }
    with open(_AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
    logger.info("Audit log written to %s", _AUDIT_LOG_PATH)


# ── AST-based import analysis ─────────────────────────────────────────────

def parse_imports(file_path: str) -> list[ImportInfo]:
    """Parse imports from a source file. Supports Python (AST), JS/Go/Java (regex)."""
    ext = os.path.splitext(file_path)[1].lower()
    try:
        text = Path(file_path).read_text(errors="replace")
    except OSError:
        return []

    if ext == ".py":
        return _parse_python_imports(text, file_path)
    elif ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        return _parse_js_imports(text, file_path)
    elif ext == ".go":
        return _parse_go_imports(text, file_path)
    elif ext == ".java":
        return _parse_java_imports(text, file_path)
    return []


def _parse_python_imports(text: str, file_path: str) -> list[ImportInfo]:
    """Parse Python imports using AST."""
    imports: list[ImportInfo] = []
    try:
        tree = ast.parse(text, filename=file_path)
    except SyntaxError:
        return []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(ImportInfo(
                    module=alias.name,
                    names=[alias.asname or alias.name.split(".")[-1]],
                    file_path=file_path,
                    line=node.lineno,
                ))
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = [a.name for a in node.names] if node.names else []
            imports.append(ImportInfo(
                module=module,
                names=names,
                file_path=file_path,
                line=node.lineno,
                is_from_import=True,
            ))
    return imports


def _parse_js_imports(text: str, file_path: str) -> list[ImportInfo]:
    """Parse JavaScript/TypeScript imports using regex."""
    imports: list[ImportInfo] = []
    # import ... from 'module'
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"""^\s*import\s+.*?\s+from\s+['"]([^'"]+)['"]""", line)
        if m:
            imports.append(ImportInfo(module=m.group(1), names=[], file_path=file_path, line=i, is_from_import=True))
            continue
        # require('module')
        m = re.search(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""", line)
        if m:
            imports.append(ImportInfo(module=m.group(1), names=[], file_path=file_path, line=i))
    return imports


def _parse_go_imports(text: str, file_path: str) -> list[ImportInfo]:
    """Parse Go imports using regex."""
    imports: list[ImportInfo] = []
    # Single import
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r'^\s*import\s+"([^"]+)"', line)
        if m:
            imports.append(ImportInfo(module=m.group(1), names=[], file_path=file_path, line=i))
    # Block import
    in_block = False
    for i, line in enumerate(text.splitlines(), 1):
        if re.match(r"^\s*import\s*\(", line):
            in_block = True
            continue
        if in_block:
            if line.strip() == ")":
                in_block = False
                continue
            m = re.match(r'\s*(?:\w+\s+)?"([^"]+)"', line)
            if m:
                imports.append(ImportInfo(module=m.group(1), names=[], file_path=file_path, line=i))
    return imports


def _parse_java_imports(text: str, file_path: str) -> list[ImportInfo]:
    """Parse Java imports using regex."""
    imports: list[ImportInfo] = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*import\s+(static\s+)?([a-zA-Z0-9_.]+)\s*;", line)
        if m:
            imports.append(ImportInfo(module=m.group(2), names=[], file_path=file_path, line=i))
    return imports


# ── Import graph ───────────────────────────────────────────────────────────

def build_import_graph(repo_path: str) -> dict[str, list[ImportInfo]]:
    """Build a map of file → imports across the codebase.

    Args:
        repo_path: Path to repository root.

    Returns:
        Dict mapping file paths to their imports.
    """
    graph: dict[str, list[ImportInfo]] = {}
    skip_dirs = {".git", "node_modules", "__pycache__", ".tox", ".venv",
                 "venv", "vendor", "dist", "build", ".eggs", ".mypy_cache"}
    supported_exts = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java"}

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in supported_exts:
                fpath = os.path.join(root, fname)
                imports = parse_imports(fpath)
                if imports:
                    graph[fpath] = imports
    return graph


# ── Call graph construction (Python-focused) ──────────────────────────────

def _parse_python_functions(text: str, file_path: str, module_name: str) -> list[FunctionDef]:
    """Parse function definitions and their calls from Python source."""
    functions: list[FunctionDef] = []
    try:
        tree = ast.parse(text, filename=file_path)
    except SyntaxError:
        return []

    class FuncVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.current_class: str | None = None

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            old = self.current_class
            self.current_class = node.name
            self.generic_visit(node)
            self.current_class = old

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            if self.current_class:
                qname = f"{module_name}.{self.current_class}.{node.name}"
            else:
                qname = f"{module_name}.{node.name}"

            calls = []
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    call_name = _extract_call_name(child)
                    if call_name:
                        calls.append(call_name)

            functions.append(FunctionDef(
                name=node.name,
                qualified_name=qname,
                file_path=file_path,
                line=node.lineno,
                calls=calls,
            ))
            self.generic_visit(node)

        visit_AsyncFunctionDef = visit_FunctionDef

    FuncVisitor().visit(tree)
    return functions


def _extract_call_name(node: ast.Call) -> str | None:
    """Extract the called function name from an AST Call node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        parts = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def find_entry_points(repo_path: str) -> list[FunctionDef]:
    """Detect entry points in the repository.

    Looks for:
    - Python: if __name__ == "__main__", Flask/FastAPI routes, CLI entry points
    - JS: package.json main, Express routes
    - Go: func main()
    - Java: public static void main
    """
    entry_points: list[FunctionDef] = []
    skip_dirs = {".git", "node_modules", "__pycache__", ".tox", ".venv",
                 "venv", "vendor", "dist", "build", ".eggs"}

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            fpath = os.path.join(root, fname)
            ext = os.path.splitext(fname)[1].lower()

            if ext == ".py":
                entry_points.extend(_find_python_entry_points(fpath, repo_path))
            elif ext in (".js", ".ts"):
                entry_points.extend(_find_js_entry_points(fpath, repo_path))
            elif ext == ".go":
                entry_points.extend(_find_go_entry_points(fpath, repo_path))
            elif ext == ".java":
                entry_points.extend(_find_java_entry_points(fpath, repo_path))

    return entry_points


def _find_python_entry_points(file_path: str, repo_path: str) -> list[FunctionDef]:
    """Find Python entry points."""
    eps: list[FunctionDef] = []
    try:
        text = Path(file_path).read_text(errors="replace")
        tree = ast.parse(text, filename=file_path)
    except (OSError, SyntaxError):
        return []

    rel_path = os.path.relpath(file_path, repo_path)
    module_name = rel_path.replace(os.sep, ".").removesuffix(".py")

    # Check for if __name__ == "__main__"
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            test = node.test
            if (isinstance(test, ast.Compare) and
                    isinstance(test.left, ast.Name) and test.left.id == "__name__" and
                    any(isinstance(c, (ast.Constant,)) and getattr(c, 'value', None) == "__main__"
                        for c in test.comparators)):
                # Collect calls inside this block
                calls = []
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        cn = _extract_call_name(child)
                        if cn:
                            calls.append(cn)
                eps.append(FunctionDef(
                    name="__main__",
                    qualified_name=f"{module_name}.__main__",
                    file_path=file_path,
                    line=node.lineno,
                    calls=calls,
                    is_entry_point=True,
                ))

    # Check for Flask/FastAPI route decorators
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                dec_name = ""
                if isinstance(dec, ast.Call):
                    dec_name = _extract_call_name_from_func(dec.func)
                elif isinstance(dec, ast.Attribute):
                    dec_name = dec.attr
                if dec_name and any(r in dec_name for r in ("route", "get", "post", "put", "delete", "patch", "api_view")):
                    calls = []
                    for child in ast.walk(node):
                        if isinstance(child, ast.Call):
                            cn = _extract_call_name(child)
                            if cn:
                                calls.append(cn)
                    eps.append(FunctionDef(
                        name=node.name,
                        qualified_name=f"{module_name}.{node.name}",
                        file_path=file_path,
                        line=node.lineno,
                        calls=calls,
                        is_entry_point=True,
                    ))

    return eps


def _extract_call_name_from_func(node: ast.expr) -> str:
    """Extract name from a function node of a decorator call."""
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _find_js_entry_points(file_path: str, repo_path: str) -> list[FunctionDef]:
    """Find JavaScript entry points (Express routes, main)."""
    eps: list[FunctionDef] = []
    try:
        text = Path(file_path).read_text(errors="replace")
    except OSError:
        return []

    rel_path = os.path.relpath(file_path, repo_path)
    for i, line in enumerate(text.splitlines(), 1):
        if re.search(r"\.(get|post|put|delete|patch)\s*\(\s*['\"/]", line):
            eps.append(FunctionDef(
                name=f"route:{line.strip()[:50]}",
                qualified_name=f"{rel_path}:route:{i}",
                file_path=file_path,
                line=i,
                is_entry_point=True,
            ))
    return eps


def _find_go_entry_points(file_path: str, repo_path: str) -> list[FunctionDef]:
    """Find Go entry points (func main)."""
    eps: list[FunctionDef] = []
    try:
        text = Path(file_path).read_text(errors="replace")
    except OSError:
        return []

    rel_path = os.path.relpath(file_path, repo_path)
    for i, line in enumerate(text.splitlines(), 1):
        if re.match(r"^\s*func\s+main\s*\(", line):
            eps.append(FunctionDef(
                name="main",
                qualified_name=f"{rel_path}:main",
                file_path=file_path,
                line=i,
                is_entry_point=True,
            ))
    return eps


def _find_java_entry_points(file_path: str, repo_path: str) -> list[FunctionDef]:
    """Find Java entry points (public static void main)."""
    eps: list[FunctionDef] = []
    try:
        text = Path(file_path).read_text(errors="replace")
    except OSError:
        return []

    rel_path = os.path.relpath(file_path, repo_path)
    for i, line in enumerate(text.splitlines(), 1):
        if re.search(r"public\s+static\s+void\s+main\s*\(", line):
            eps.append(FunctionDef(
                name="main",
                qualified_name=f"{rel_path}:main",
                file_path=file_path,
                line=i,
                is_entry_point=True,
            ))
    return eps


# ── Call graph building ────────────────────────────────────────────────────

def build_call_graph(
    repo_path: str,
    target_package: str,
) -> tuple[list[FunctionDef], list[CallEdge]]:
    """Build a call graph for the repository focused on target package.

    Args:
        repo_path: Path to repository root.
        target_package: Package name to trace (e.g., "jinja2").

    Returns:
        Tuple of (all function defs, call edges).
    """
    all_functions: list[FunctionDef] = []
    all_edges: list[CallEdge] = []
    skip_dirs = {".git", "node_modules", "__pycache__", ".tox", ".venv",
                 "venv", "vendor", "dist", "build", ".eggs"}

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(root, fname)
            try:
                text = Path(fpath).read_text(errors="replace")
            except OSError:
                continue
            rel_path = os.path.relpath(fpath, repo_path)
            module_name = rel_path.replace(os.sep, ".").removesuffix(".py")
            funcs = _parse_python_functions(text, fpath, module_name)
            all_functions.extend(funcs)

            for func in funcs:
                for call in func.calls:
                    all_edges.append(CallEdge(
                        caller=func.qualified_name,
                        callee=call,
                        file_path=fpath,
                        line=func.line,
                    ))

    return all_functions, all_edges


# ── Vulnerability function mapping ────────────────────────────────────────

_VULN_FUNCTIONS_PATH = Path(__file__).parent.parent / "config" / "vuln_functions.json"


def get_vulnerable_functions(cve_id: str) -> list[str]:
    """Get known vulnerable functions for a CVE.

    Checks local mapping first, then returns empty list.
    """
    if _VULN_FUNCTIONS_PATH.exists():
        try:
            data = json.loads(_VULN_FUNCTIONS_PATH.read_text())
            return data.get(cve_id, [])
        except (json.JSONDecodeError, OSError):
            pass
    return []


# ── Trace vulnerable functions ─────────────────────────────────────────────

def trace_vulnerable_functions(
    functions: list[FunctionDef],
    edges: list[CallEdge],
    entry_points: list[FunctionDef],
    vuln_functions: list[str],
    target_package: str,
) -> tuple[str, list[CallChain], bool]:
    """Check if any entry point can reach a vulnerable function.

    Returns:
        (verdict, call_chains, has_dynamic_dispatch)
    """
    if not vuln_functions:
        # If no specific functions known, check if the package is called at all
        vuln_functions = [target_package]

    # Build adjacency from call edges
    adjacency: dict[str, list[tuple[str, str, int]]] = {}  # caller -> [(callee, file, line)]
    for edge in edges:
        adjacency.setdefault(edge.caller, []).append((edge.callee, edge.file_path, edge.line))

    # Check for dynamic dispatch patterns
    has_dynamic = _check_dynamic_dispatch(functions)

    # BFS from each entry point
    chains: list[CallChain] = []
    for ep in entry_points:
        chain = _bfs_to_target(ep.qualified_name, adjacency, vuln_functions, target_package, functions)
        if chain:
            chains.append(chain)

    if chains:
        return REACHABLE, chains, has_dynamic
    
    # Check if package is imported at all
    all_calls = set()
    for f in functions:
        all_calls.update(f.calls)
    
    pkg_referenced = any(
        target_package in call or any(vf in call for vf in vuln_functions)
        for call in all_calls
    )
    
    if not pkg_referenced:
        return IMPORTED_ONLY, [], has_dynamic
    
    if has_dynamic:
        return INCONCLUSIVE, [], has_dynamic
    
    return NOT_REACHABLE, [], has_dynamic


def _bfs_to_target(
    start: str,
    adjacency: dict[str, list[tuple[str, str, int]]],
    vuln_functions: list[str],
    target_package: str,
    all_functions: list[FunctionDef],
) -> CallChain | None:
    """BFS from entry point to find path to vulnerable function."""
    # Get start function info
    start_func = next((f for f in all_functions if f.qualified_name == start), None)
    if not start_func:
        return None

    # Also check direct calls from entry point
    for call in start_func.calls:
        if _matches_vuln(call, vuln_functions, target_package):
            return CallChain(steps=[
                (start, start_func.file_path, start_func.line),
                (call, start_func.file_path, start_func.line),
            ])

    from collections import deque
    visited = {start}
    queue: deque[list[tuple[str, str, int]]] = deque()
    queue.append([(start, start_func.file_path, start_func.line)])

    while queue:
        path = queue.popleft()
        current = path[-1][0]

        for callee, fp, ln in adjacency.get(current, []):
            if _matches_vuln(callee, vuln_functions, target_package):
                return CallChain(steps=path + [(callee, fp, ln)])
            if callee not in visited:
                visited.add(callee)
                # Find the function def for callee to get its file/line
                callee_func = next((f for f in all_functions if f.qualified_name == callee), None)
                if callee_func:
                    queue.append(path + [(callee, callee_func.file_path, callee_func.line)])

    return None


def _matches_vuln(call_name: str, vuln_functions: list[str], target_package: str) -> bool:
    """Check if a call name matches any vulnerable function."""
    for vf in vuln_functions:
        if vf in call_name or call_name.endswith(f".{vf}"):
            return True
    if target_package in call_name:
        return True
    return False


def _check_dynamic_dispatch(functions: list[FunctionDef]) -> bool:
    """Check for dynamic dispatch patterns (getattr, eval, etc.)."""
    dynamic_patterns = {"getattr", "eval", "exec", "__import__", "importlib.import_module"}
    for func in functions:
        for call in func.calls:
            if call in dynamic_patterns or any(dp in call for dp in dynamic_patterns):
                return True
    return False


# ── Claude integration (sanitized) ────────────────────────────────────────

async def _get_claude_interpretation(
    context: SanitizedContext,
) -> str:
    """Get Claude's interpretation of the execution path.

    ONLY sends sanitized metadata — never source code.
    """
    prompt_text = context.to_prompt_text()

    # Double-check: assert no source code
    assert not contains_source_code(prompt_text), (
        "SECURITY VIOLATION: Attempted to send source code to Claude!"
    )

    # Audit log what we're sending
    audit_log(context.to_dict())

    from sentinel.config import get_api_key, get_model
    import anthropic

    api_key = get_api_key()
    if not api_key:
        return "Claude API key not configured — skipping interpretation."

    client = anthropic.Anthropic(api_key=api_key)
    model = get_model()

    system = (
        "You are a security analyst interpreting call graph data. "
        "You receive ONLY metadata (function names, import names, call edges) — "
        "never source code. Based on the call graph structure and CVE description, "
        "assess whether the vulnerable code path is likely exercised. "
        "Be concise. State your confidence level."
    )

    message = client.messages.create(
        model=model,
        max_tokens=1024,
        system=system,
        messages=[{"role": "user", "content": prompt_text}],
    )

    return message.content[0].text


# ── Main analysis pipeline ─────────────────────────────────────────────────

async def analyze_execution_path(
    repo_path: str,
    cve_id: str,
    local_only: bool = False,
) -> ExecutionPathResult:
    """Full execution path analysis pipeline.

    Args:
        repo_path: Path to repository.
        cve_id: CVE to check.
        local_only: If True, skip Claude interpretation.

    Returns:
        ExecutionPathResult with verdict and call chains.
    """
    # Get vulnerable functions for this CVE
    vuln_functions = get_vulnerable_functions(cve_id)

    # Determine target package from CVE data
    target_package = await _get_target_package(cve_id)
    if not target_package:
        return ExecutionPathResult(
            verdict=INCONCLUSIVE,
            cve_id=cve_id,
            target_package="unknown",
            vulnerable_functions=vuln_functions,
            details="Could not determine affected package from CVE data.",
        )

    # Build import graph
    import_graph = build_import_graph(repo_path)

    # Find imports of target package
    target_imports: list[ImportInfo] = []
    for file_path, imports in import_graph.items():
        for imp in imports:
            if target_package in imp.module or imp.module.startswith(target_package):
                target_imports.append(imp)

    if not target_imports:
        return ExecutionPathResult(
            verdict=IMPORTED_ONLY,
            cve_id=cve_id,
            target_package=target_package,
            vulnerable_functions=vuln_functions,
            imports_found=[],
            details=f"Package '{target_package}' not directly imported in source code.",
        )

    # Find entry points
    entry_points = find_entry_points(repo_path)

    # Build call graph
    functions, edges = build_call_graph(repo_path, target_package)

    # Trace
    verdict, chains, has_dynamic = trace_vulnerable_functions(
        functions, edges, entry_points, vuln_functions, target_package
    )

    result = ExecutionPathResult(
        verdict=verdict,
        cve_id=cve_id,
        target_package=target_package,
        vulnerable_functions=vuln_functions,
        call_chains=chains,
        entry_points=[ep.qualified_name for ep in entry_points],
        imports_found=target_imports,
        has_dynamic_dispatch=has_dynamic,
    )

    # Claude interpretation if requested
    if not local_only and verdict in (REACHABLE, INCONCLUSIVE):
        try:
            ctx = SanitizedContext()
            ctx.package_name = target_package
            ctx.cve_id = cve_id
            ctx.vulnerable_functions = vuln_functions
            ctx.entry_points = [ep.qualified_name for ep in entry_points]
            ctx.call_edges = [
                {"caller": e.caller, "callee": e.callee, "file": os.path.basename(e.file_path), "line": str(e.line)}
                for e in edges[:100]  # Limit edges
            ]
            ctx.file_names = list(set(os.path.basename(f.file_path) for f in functions))
            ctx.import_names = [f"{i.module}.{','.join(i.names)}" for i in target_imports]
            ctx.function_names = [f.name for f in functions[:100]]

            # Get CVE description for context
            try:
                from sentinel.fetcher import fetch_cve_data
                cve_data = await fetch_cve_data(cve_id)
                ctx.cve_description = cve_data.get("raw_context", "")[:500]
            except Exception:
                ctx.cve_description = f"CVE {cve_id}"

            result.claude_interpretation = await _get_claude_interpretation(ctx)
        except Exception as e:
            logger.warning("Claude interpretation failed: %s", e)
            result.claude_interpretation = f"(Claude analysis unavailable: {e})"

    return result


async def _get_target_package(cve_id: str) -> str | None:
    """Determine the target package name from CVE data."""
    try:
        from sentinel.fetcher import fetch_cve_data
        cve_data = await fetch_cve_data(cve_id)
        sources = cve_data.get("sources", {})
        osv = sources.get("osv", {})
        for affected in osv.get("affected", []):
            pkg = affected.get("package", {})
            name = pkg.get("name", "")
            if name:
                return name.lower()
    except Exception as e:
        logger.warning("Could not fetch CVE data for %s: %s", cve_id, e)
    return None
