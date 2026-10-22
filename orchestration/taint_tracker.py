"""
VAITP Taint Tracking: Source-to-Sink Data Flow Analysis

Performs lightweight intra-procedural taint analysis using Python AST.
Tracks how untrusted data (sources) flows to dangerous operations (sinks).

Sources: function parameters, input(), request.*, os.environ, file reads
Sinks: exec, eval, subprocess, os.system, open, sql execute, template render

A taint flow is: source → [transforms] → sink
"""

import ast
import os
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field


# Known taint sources (where untrusted data enters)
TAINT_SOURCES = {
    # Function calls that return untrusted data
    "input": "user_input",
    "read": "file_read",
    "readline": "file_read",
    "readlines": "file_read",
    "recv": "network_input",
    "recvfrom": "network_input",
    "urlopen": "network_input",
    # Attribute access patterns
    "request.args": "http_param",
    "request.form": "http_param",
    "request.json": "http_param",
    "request.data": "http_param",
    "request.headers": "http_header",
    "request.cookies": "http_cookie",
    "request.files": "http_upload",
    "request.values": "http_param",
    "request.get_json": "http_param",
    "os.environ": "env_var",
    "sys.argv": "cli_arg",
}

# Known taint sinks (where untrusted data is dangerous)
TAINT_SINKS = {
    "eval": ("code_injection", "CWE-94"),
    "exec": ("code_injection", "CWE-94"),
    "compile": ("code_injection", "CWE-94"),
    "os.system": ("command_injection", "CWE-78"),
    "os.popen": ("command_injection", "CWE-78"),
    "subprocess.call": ("command_injection", "CWE-78"),
    "subprocess.run": ("command_injection", "CWE-78"),
    "subprocess.Popen": ("command_injection", "CWE-78"),
    "cursor.execute": ("sql_injection", "CWE-89"),
    "cursor.executemany": ("sql_injection", "CWE-89"),
    "cursor.executescript": ("sql_injection", "CWE-89"),
    "render_template_string": ("ssti", "CWE-1336"),
    "Template": ("ssti", "CWE-1336"),
    "from_string": ("ssti", "CWE-1336"),
    "open": ("path_traversal", "CWE-22"),
    "redirect": ("open_redirect", "CWE-601"),
    "send_file": ("path_traversal", "CWE-22"),
    "pickle.loads": ("deserialization", "CWE-502"),
    "yaml.load": ("deserialization", "CWE-502"),
    "yaml.unsafe_load": ("deserialization", "CWE-502"),
    "marshal.loads": ("deserialization", "CWE-502"),
    "os.symlink": ("symlink_following", "CWE-59"),
    "extractall": ("path_traversal", "CWE-22"),
    "requests.get": ("ssrf", "CWE-918"),
    "requests.post": ("ssrf", "CWE-918"),
    "urllib.request.urlopen": ("ssrf", "CWE-918"),
    "httpx.get": ("ssrf", "CWE-918"),
}

# Sanitizers that break taint flow
SANITIZERS = {
    "shlex.quote", "shlex.split",
    "html.escape", "markupsafe.escape",
    "int", "float", "bool",
    "os.path.basename", "os.path.normpath",
    "urllib.parse.quote", "urllib.parse.urlencode",
    "bleach.clean",
    "re.escape",
    "parameterized_query",  # conceptual
}


@dataclass
class TaintFlow:
    """Represents a data flow from source to sink."""
    file_path: str
    function_name: str
    source_line: int
    source_type: str  # e.g., "user_input", "http_param"
    source_var: str  # variable name at source
    sink_line: int
    sink_type: str  # e.g., "command_injection", "sql_injection"
    sink_cwe: str
    sink_call: str  # e.g., "os.system"
    tainted_var: str  # variable name at sink
    path: List[str]  # variable names along the flow
    sanitized: bool  # True if a sanitizer was found in the path
    confidence: float


@dataclass
class TaintState:
    """Tracks tainted variables within a function."""
    tainted: Dict[str, Tuple[str, int, str]] = field(default_factory=dict)
    # var_name -> (source_type, source_line, original_source_var)


def analyze_taint_flows(repo_path: str, exclude_tests: bool = True) -> List[TaintFlow]:
    """
    Perform intra-procedural taint analysis across all Python files in a repo.
    Returns a list of potential source-to-sink flows (deduplicated).
    """
    flows = []
    repo = Path(repo_path)

    for py_file in repo.rglob("*.py"):
        rel_path = str(py_file.relative_to(repo))
        if exclude_tests and any(skip in rel_path for skip in
                                  ["test", "docs", "venv", ".venv", "__pycache__",
                                   "node_modules", ".git", "examples"]):
            continue

        try:
            source = py_file.read_text(errors="ignore")
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue

        # Analyze each function
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_flows = _analyze_function_taint(node, source, rel_path)
                flows.extend(func_flows)

    # Deduplicate flows (same file, function, source_var, sink_call, sink_line)
    seen = set()
    unique_flows = []
    for flow in flows:
        key = (flow.file_path, flow.function_name, flow.source_var,
               flow.sink_call, flow.sink_line)
        if key not in seen:
            seen.add(key)
            unique_flows.append(flow)

    # Sort by confidence (unsanitized flows first)
    unique_flows.sort(key=lambda f: (not f.sanitized, f.confidence), reverse=True)
    return unique_flows


def _analyze_function_taint(
    func_node: ast.FunctionDef,
    source_code: str,
    file_path: str,
) -> List[TaintFlow]:
    """Analyze taint flows within a single function."""
    flows = []
    state = TaintState()

    # Mark function parameters as tainted (they come from callers)
    for arg in func_node.args.args:
        arg_name = arg.arg
        if arg_name != "self" and arg_name != "cls":
            state.tainted[arg_name] = ("function_param", func_node.lineno, arg_name)

    # Walk statements in order
    for stmt in ast.walk(func_node):
        # Track assignments that propagate taint
        if isinstance(stmt, ast.Assign):
            _process_assignment(stmt, state)
        elif isinstance(stmt, ast.AugAssign):
            _process_aug_assignment(stmt, state)

        # Check for sink calls with tainted arguments
        if isinstance(stmt, ast.Call) or (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)):
            call = stmt if isinstance(stmt, ast.Call) else stmt.value
            sink_flows = _check_sink_call(call, state, file_path, func_node.name)
            flows.extend(sink_flows)

        # Also check calls nested in expressions
        for child in ast.walk(stmt):
            if isinstance(child, ast.Call) and child is not stmt:
                sink_flows = _check_sink_call(child, state, file_path, func_node.name)
                flows.extend(sink_flows)

    return flows


def _get_call_name(call: ast.Call) -> str:
    """Extract the full call name (e.g., 'os.system', 'cursor.execute')."""
    if isinstance(call.func, ast.Name):
        return call.func.id
    elif isinstance(call.func, ast.Attribute):
        if isinstance(call.func.value, ast.Name):
            return f"{call.func.value.id}.{call.func.attr}"
        return call.func.attr
    return ""


def _get_var_names_in_expr(expr: ast.expr) -> Set[str]:
    """Extract all variable names referenced in an expression."""
    names = set()
    for node in ast.walk(expr):
        if isinstance(node, ast.Name):
            names.add(node.id)
    return names


def _process_assignment(stmt: ast.Assign, state: TaintState):
    """Track taint propagation through assignments."""
    # Check if the RHS contains any tainted variables
    rhs_vars = _get_var_names_in_expr(stmt.value)
    tainted_sources = [(v, state.tainted[v]) for v in rhs_vars if v in state.tainted]

    # Check if RHS is a taint source (e.g., input(), request.args.get())
    if isinstance(stmt.value, ast.Call):
        call_name = _get_call_name(stmt.value)
        for source_pattern, source_type in TAINT_SOURCES.items():
            if call_name == source_pattern or call_name.endswith(source_pattern):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        state.tainted[target.id] = (source_type, stmt.lineno, target.id)
                return

    # Propagate taint from RHS to LHS
    if tainted_sources:
        src_type, src_line, src_var = tainted_sources[0][1]
        for target in stmt.targets:
            if isinstance(target, ast.Name):
                # Check if assignment includes a sanitizer
                if isinstance(stmt.value, ast.Call):
                    call_name = _get_call_name(stmt.value)
                    if any(san in call_name for san in SANITIZERS):
                        # Sanitized — remove taint
                        state.tainted.pop(target.id, None)
                        continue
                state.tainted[target.id] = (src_type, src_line, src_var)


def _process_aug_assignment(stmt: ast.AugAssign, state: TaintState):
    """Track taint through augmented assignments (+=, etc.)."""
    if isinstance(stmt.target, ast.Name):
        rhs_vars = _get_var_names_in_expr(stmt.value)
        if any(v in state.tainted for v in rhs_vars):
            # Target becomes tainted if any RHS var is tainted
            if stmt.target.id not in state.tainted:
                tainted_var = next(v for v in rhs_vars if v in state.tainted)
                state.tainted[stmt.target.id] = state.tainted[tainted_var]


def _check_sink_call(
    call: ast.Call,
    state: TaintState,
    file_path: str,
    func_name: str,
) -> List[TaintFlow]:
    """Check if a call is a sink with tainted arguments."""
    flows = []
    call_name = _get_call_name(call)

    # Check if this call is a known sink
    sink_info = None
    for sink_pattern, info in TAINT_SINKS.items():
        if call_name == sink_pattern or call_name.endswith(sink_pattern.split(".")[-1]):
            sink_info = info
            break

    if not sink_info:
        return flows

    sink_type, sink_cwe = sink_info

    # Check if any argument is tainted
    for arg in call.args:
        arg_vars = _get_var_names_in_expr(arg)
        for var in arg_vars:
            if var in state.tainted:
                src_type, src_line, src_var = state.tainted[var]
                flows.append(TaintFlow(
                    file_path=file_path,
                    function_name=func_name,
                    source_line=src_line,
                    source_type=src_type,
                    source_var=src_var,
                    sink_line=getattr(call, 'lineno', 0),
                    sink_type=sink_type,
                    sink_cwe=sink_cwe,
                    sink_call=call_name,
                    tainted_var=var,
                    path=[src_var, var] if src_var != var else [var],
                    sanitized=False,
                    confidence=0.8 if src_type in ("user_input", "http_param") else 0.5,
                ))

    # Check keyword arguments too
    for kw in call.keywords:
        if kw.value:
            kw_vars = _get_var_names_in_expr(kw.value)
            for var in kw_vars:
                if var in state.tainted:
                    src_type, src_line, src_var = state.tainted[var]
                    # shell=True with tainted command is especially dangerous
                    extra_confidence = 0.2 if kw.arg == "shell" else 0.0
                    flows.append(TaintFlow(
                        file_path=file_path,
                        function_name=func_name,
                        source_line=src_line,
                        source_type=src_type,
                        source_var=src_var,
                        sink_line=getattr(call, 'lineno', 0),
                        sink_type=sink_type,
                        sink_cwe=sink_cwe,
                        sink_call=call_name,
                        tainted_var=var,
                        path=[src_var, var] if src_var != var else [var],
                        sanitized=False,
                        confidence=min(0.8 + extra_confidence, 1.0),
                    ))

    return flows


def format_taint_flows(flows: List[TaintFlow], max_display: int = 20) -> str:
    """Format taint flows for display."""
    if not flows:
        return "  No taint flows detected."

    lines = []
    for i, flow in enumerate(flows[:max_display], 1):
        sanitized_mark = " [SANITIZED]" if flow.sanitized else ""
        lines.append(
            f"  {i:2d}. {flow.file_path}:{flow.function_name}\n"
            f"      Source: {flow.source_type} (line {flow.source_line}, var={flow.source_var})\n"
            f"      Sink:   {flow.sink_call} → {flow.sink_type} [{flow.sink_cwe}] (line {flow.sink_line})\n"
            f"      Flow:   {' → '.join(flow.path)}{sanitized_mark}\n"
            f"      Confidence: {flow.confidence:.2f}"
        )
    return "\n".join(lines)
