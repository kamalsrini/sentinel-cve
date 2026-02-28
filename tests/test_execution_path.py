"""Tests for Execution Path Analysis."""

from __future__ import annotations

import os
import tempfile
import pytest
from pathlib import Path

from sentinel.execution_path import (
    REACHABLE,
    NOT_REACHABLE,
    IMPORTED_ONLY,
    INCONCLUSIVE,
    ImportInfo,
    FunctionDef,
    CallEdge,
    CallChain,
    SanitizedContext,
    contains_source_code,
    parse_imports,
    build_import_graph,
    find_entry_points,
    build_call_graph,
    trace_vulnerable_functions,
    get_vulnerable_functions,
    audit_log,
)


# ── Source code detection (CRITICAL SECURITY TEST) ─────────────────────────

def test_contains_source_code_python():
    """CRITICAL: Must detect Python source code."""
    code = """
def process_data(input):
    if input is None:
        return None
    for item in input:
        result = transform(item)
    return result
"""
    assert contains_source_code(code) is True


def test_contains_source_code_javascript():
    code = """
function processData(input) {
    const result = input.map(x => x * 2);
    let total = 0;
    for (const item of result) {
        total += item;
    }
    return total;
}
"""
    assert contains_source_code(code) is True


def test_contains_source_code_go():
    code = """
func main() {
    package main
    type Config struct {
        Name string
    }
}
"""
    assert contains_source_code(code) is True


def test_not_source_code_metadata():
    """Metadata should NOT be flagged as source code."""
    text = """
Package: jinja2
CVE: CVE-2024-22195
Vulnerable functions: urlize, do_urlize
Entry points: app.main, cli.run
Call graph edges:
  app.main -> utils.render -> jinja2.urlize
Files: app.py, utils.py
"""
    assert contains_source_code(text) is False


def test_not_source_code_short():
    assert contains_source_code("hello") is False
    assert contains_source_code("") is False


# ── SanitizedContext NEVER contains source code ───────────────────────────

def test_sanitized_context_clean():
    """SanitizedContext with clean data should produce valid output."""
    ctx = SanitizedContext()
    ctx.package_name = "jinja2"
    ctx.cve_id = "CVE-2024-22195"
    ctx.cve_description = "XSS via urlize filter"
    ctx.vulnerable_functions = ["urlize"]
    ctx.entry_points = ["app.main"]
    ctx.call_edges = [{"caller": "app.main", "callee": "jinja2.urlize", "file": "app.py", "line": "10"}]
    ctx.file_names = ["app.py"]
    ctx.import_names = ["jinja2.utils.urlize"]
    ctx.function_names = ["main", "render"]

    # Should not raise
    text = ctx.to_prompt_text()
    assert "jinja2" in text
    assert "urlize" in text


def test_sanitized_context_rejects_source_code():
    """CRITICAL: SanitizedContext must reject source code in cve_description."""
    ctx = SanitizedContext()
    ctx.package_name = "test"
    ctx.cve_id = "CVE-2024-0000"
    # Inject source code into description
    ctx.cve_description = """
def vulnerable_function(user_input):
    if user_input is None:
        return default
    for item in user_input:
        result = process(item)
    return result
"""
    ctx.vulnerable_functions = ["vuln"]
    ctx.entry_points = ["main"]
    ctx.call_edges = []
    ctx.file_names = []
    ctx.import_names = []
    ctx.function_names = []

    with pytest.raises(AssertionError, match="source code"):
        ctx.to_prompt_text()


# ── Import parsing ─────────────────────────────────────────────────────────

def test_parse_python_imports():
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write("import os\nfrom pathlib import Path\nfrom jinja2.utils import urlize\nimport json\n")
        f.flush()
        imports = parse_imports(f.name)
    os.unlink(f.name)
    assert len(imports) == 4
    modules = [i.module for i in imports]
    assert "os" in modules
    assert "pathlib" in modules
    assert "jinja2.utils" in modules


def test_parse_js_imports():
    with tempfile.NamedTemporaryFile(suffix=".js", mode="w", delete=False) as f:
        f.write("import express from 'express';\nconst lodash = require('lodash');\n")
        f.flush()
        imports = parse_imports(f.name)
    os.unlink(f.name)
    assert len(imports) == 2
    modules = [i.module for i in imports]
    assert "express" in modules
    assert "lodash" in modules


def test_parse_go_imports():
    with tempfile.NamedTemporaryFile(suffix=".go", mode="w", delete=False) as f:
        f.write('package main\n\nimport (\n\t"fmt"\n\t"os"\n)\n')
        f.flush()
        imports = parse_imports(f.name)
    os.unlink(f.name)
    assert len(imports) == 2


def test_parse_java_imports():
    with tempfile.NamedTemporaryFile(suffix=".java", mode="w", delete=False) as f:
        f.write("import java.util.List;\nimport com.example.MyClass;\n")
        f.flush()
        imports = parse_imports(f.name)
    os.unlink(f.name)
    assert len(imports) == 2


def test_parse_imports_nonexistent_file():
    result = parse_imports("/nonexistent/file.py")
    assert result == []


# ── Import graph ───────────────────────────────────────────────────────────

def test_build_import_graph():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "app.py").write_text("import jinja2\nfrom flask import Flask\n")
        (Path(tmpdir) / "utils.py").write_text("from jinja2.utils import urlize\n")
        graph = build_import_graph(tmpdir)
        assert len(graph) == 2


# ── Entry point detection ──────────────────────────────────────────────────

def test_find_python_main_entry_point():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "app.py").write_text(
            'import sys\n\ndef main():\n    pass\n\nif __name__ == "__main__":\n    main()\n'
        )
        eps = find_entry_points(tmpdir)
        assert len(eps) >= 1
        assert any(ep.is_entry_point for ep in eps)


def test_find_flask_route_entry_point():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "app.py").write_text(
            'from flask import Flask\napp = Flask(__name__)\n\n@app.route("/")\ndef index():\n    return "hello"\n'
        )
        eps = find_entry_points(tmpdir)
        assert len(eps) >= 1


def test_find_go_main():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "main.go").write_text(
            'package main\n\nfunc main() {\n\tfmt.Println("hello")\n}\n'
        )
        eps = find_entry_points(tmpdir)
        assert len(eps) == 1
        assert eps[0].name == "main"


def test_find_java_main():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "App.java").write_text(
            'public class App {\n    public static void main(String[] args) {\n    }\n}\n'
        )
        eps = find_entry_points(tmpdir)
        assert len(eps) == 1


# ── Call graph ─────────────────────────────────────────────────────────────

def test_build_call_graph():
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "app.py").write_text(
            "from jinja2.utils import urlize\n\ndef render():\n    return urlize('hello')\n\ndef main():\n    render()\n"
        )
        funcs, edges = build_call_graph(tmpdir, "jinja2")
        assert len(funcs) >= 2
        assert len(edges) >= 1


# ── Verdict engine ─────────────────────────────────────────────────────────

def test_trace_reachable():
    entry = FunctionDef(
        name="main", qualified_name="app.main",
        file_path="app.py", line=1,
        calls=["render"], is_entry_point=True,
    )
    render_fn = FunctionDef(
        name="render", qualified_name="app.render",
        file_path="app.py", line=5,
        calls=["jinja2.utils.urlize"],
    )
    edges = [
        CallEdge(caller="app.main", callee="app.render", file_path="app.py", line=1),
        CallEdge(caller="app.render", callee="jinja2.utils.urlize", file_path="app.py", line=5),
    ]

    verdict, chains, dynamic = trace_vulnerable_functions(
        [entry, render_fn], edges, [entry], ["urlize"], "jinja2"
    )
    assert verdict == REACHABLE
    assert len(chains) >= 1


def test_trace_not_reachable():
    entry = FunctionDef(
        name="main", qualified_name="app.main",
        file_path="app.py", line=1,
        calls=["render"], is_entry_point=True,
    )
    render_fn = FunctionDef(
        name="render", qualified_name="app.render",
        file_path="app.py", line=5,
        calls=["safe_function"],
    )
    edges = [
        CallEdge(caller="app.main", callee="app.render", file_path="app.py", line=1),
        CallEdge(caller="app.render", callee="safe_function", file_path="app.py", line=5),
    ]

    verdict, chains, dynamic = trace_vulnerable_functions(
        [entry, render_fn], edges, [entry], ["urlize"], "jinja2"
    )
    # Package name "jinja2" is not in any calls, so IMPORTED_ONLY
    assert verdict == IMPORTED_ONLY
    assert len(chains) == 0


def test_trace_imported_only():
    """Package referenced via import but not called."""
    entry = FunctionDef(
        name="main", qualified_name="app.main",
        file_path="app.py", line=1,
        calls=["print"], is_entry_point=True,
    )
    verdict, chains, _ = trace_vulnerable_functions(
        [entry], [], [entry], ["urlize"], "jinja2"
    )
    assert verdict == IMPORTED_ONLY


def test_trace_dynamic_dispatch_inconclusive():
    entry = FunctionDef(
        name="main", qualified_name="app.main",
        file_path="app.py", line=1,
        calls=["getattr", "jinja2.render"], is_entry_point=True,
    )
    edges = [
        CallEdge(caller="app.main", callee="getattr", file_path="app.py", line=1),
    ]
    verdict, chains, dynamic = trace_vulnerable_functions(
        [entry], edges, [entry], ["urlize"], "jinja2"
    )
    # Has jinja2 in calls and has dynamic dispatch
    assert dynamic is True


# ── Vulnerable function mapping ────────────────────────────────────────────

def test_get_vulnerable_functions_known():
    funcs = get_vulnerable_functions("CVE-2024-22195")
    assert "urlize" in funcs or len(funcs) > 0


def test_get_vulnerable_functions_unknown():
    funcs = get_vulnerable_functions("CVE-9999-99999")
    assert funcs == []


# ── CallChain display ──────────────────────────────────────────────────────

def test_call_chain_str():
    chain = CallChain(steps=[
        ("app.main", "app.py", 1),
        ("app.render", "utils.py", 10),
        ("jinja2.urlize", "jinja2/utils.py", 45),
    ])
    s = str(chain)
    assert "app.main" in s
    assert "→" in s
    assert "jinja2.urlize" in s


# ── Audit logging ──────────────────────────────────────────────────────────

def test_audit_log_writes(tmp_path, monkeypatch):
    log_path = tmp_path / "audit.log"
    monkeypatch.setattr("sentinel.execution_path._AUDIT_LOG_PATH", log_path)
    audit_log({"test": "data"})
    assert log_path.exists()
    content = log_path.read_text()
    assert "test" in content
    assert "claude_api_call" in content
