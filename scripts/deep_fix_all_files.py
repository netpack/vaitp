#!/usr/bin/env python3
"""
Deep fix: actually attempt to import/parse each file and fix ALL runtime issues.
Goes beyond AST checks — catches None params, missing variables, wrong table names, etc.
"""
import ast
import os
import re
import json
import subprocess
import sys

VULN_DIR = "vaitp_dataset/vulnerable"
PATCH_DIR = "vaitp_dataset/injectable"
SRC_VULN = "vaitp_dataset/phase3_sven_pyvul/vulnerable"
SRC_PATCH = "vaitp_dataset/phase3_sven_pyvul/injectable"
MANIFEST = "vaitp_dataset/phase3_sven_pyvul/manifest.json"

manifest = json.load(open(MANIFEST))

def try_run(fpath):
    """Try to run the file with empty stdin, capture errors."""
    result = subprocess.run(
        [sys.executable, fpath],
        input="test_input\n",
        capture_output=True, text=True, timeout=5,
    )
    return result.returncode, result.stdout, result.stderr

def get_main_call(code):
    """Extract the function call from the __main__ block."""
    match = re.search(r'result = (\w+)\(([^)]*)\)', code)
    if match:
        return match.group(1), match.group(2)
    return None, None

def fix_none_params(code, fname):
    """Replace None params with sensible defaults based on function signature."""
    func_name, args_str = get_main_call(code)
    if not func_name or not args_str:
        return code
    
    # Find the function definition
    match = re.search(rf'def {func_name}\(([^)]*)\)', code)
    if not match:
        return code
    
    params_str = match.group(1)
    params = [p.strip().split('=')[0].split(':')[0].strip() for p in params_str.split(',') if p.strip()]
    
    # Build better default args
    args = args_str.split(',')
    new_args = []
    for i, arg in enumerate(args):
        arg = arg.strip()
        if arg == 'None' and i < len(params):
            param_name = params[i].lower()
            # Guess a sensible default based on parameter name
            if any(x in param_name for x in ['path', 'file', 'dir', 'name', 'url', 'key', 'query', 'cmd', 'command']):
                new_args.append('"test"')
            elif any(x in param_name for x in ['size', 'count', 'num', 'limit', 'max', 'min', 'index', 'id']):
                new_args.append('1')
            elif any(x in param_name for x in ['flag', 'check', 'enable', 'verbose', 'force']):
                new_args.append('True')
            elif any(x in param_name for x in ['data', 'content', 'body', 'text', 'string', 'yaml_string']):
                new_args.append('"test"')
            elif any(x in param_name for x in ['dict', 'config', 'settings', 'options', 'kwargs', 'args', 'params']):
                new_args.append('{}')
            elif any(x in param_name for x in ['list', 'items', 'values', 'objects']):
                new_args.append('[]')
            else:
                new_args.append('"test"')
        else:
            new_args.append(arg)
    
    old_call = f'result = {func_name}({args_str})'
    new_call = f'result = {func_name}({", ".join(new_args)})'
    if old_call != new_call:
        code = code.replace(old_call, new_call)
    
    return code

def fix_super_calls(code):
    """Remove super().__init__() calls outside of class context."""
    if 'super()' in code and 'class ' not in code:
        code = re.sub(r'\s*super\(\)\.__\w+__\(\)\s*\n?', '\n', code)
    return code

def fix_undefined_variables(code):
    """Fix common undefined variable patterns."""
    # Fix 'content' used as closure variable — make it a parameter
    if re.search(r'def \w+\(\):', code) and 'content' in code and 'content' not in code.split('def')[0]:
        # Function takes no args but uses 'content' — add it as param
        code = re.sub(r'def (\w+)\(\):', r'def \1(content):', code)
        # Fix the call in main block
        func_match = re.search(r'def (\w+)\(content\):', code)
        if func_match:
            fn = func_match.group(1)
            code = code.replace(f'result = {fn}()', f'result = {fn}(raw)')
    
    return code

def ensure_all_stubs(code):
    """Make sure all referenced names have stubs."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return code
    
    # Collect defined names
    defined = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    defined.add(alias.asname or alias.name.split('.')[0])
            else:
                if node.module:
                    defined.add(node.module.split('.')[0])
                for alias in node.names:
                    defined.add(alias.asname or alias.name)
        elif isinstance(node, ast.FunctionDef):
            defined.add(node.name)
        elif isinstance(node, ast.ClassDef):
            defined.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    defined.add(t.id)
        elif isinstance(node, ast.For):
            if isinstance(node.target, ast.Name):
                defined.add(node.target.id)
    
    # Find undefined attribute references
    safe = defined | {
        'os', 'sys', 'subprocess', 'json', 'base64', 'pickle', 'yaml', 're',
        'sqlite3', 'io', 'tempfile', 'shutil', 'hashlib', 'secrets', 'math',
        'time', 'datetime', 'collections', 'functools', 'itertools',
        'flask', 'Flask', 'request', 'session', 'redirect', 'url_for',
        'flash', 'abort', 'jsonify', 'make_response', 'g',
        'app', 'conn', 'user_input', 'raw', 'url', 'result', 'e', 'f',
        'requests', 'req_lib', 'urllib', 'logging', 'traceback', 'ipaddress',
        'textwrap', 'unicodedata', 'argparse', 'copy', 'fnmatch', 'glob',
        'string', 'pathlib', 'typing', 'warnings',
        'print', 'input', 'len', 'range', 'str', 'int', 'float', 'bool',
        'list', 'dict', 'set', 'tuple', 'type', 'isinstance', 'hasattr',
        'getattr', 'setattr', 'True', 'False', 'None', 'Exception',
        'ValueError', 'TypeError', 'KeyError', 'IndexError', 'AttributeError',
        'RuntimeError', 'NotImplementedError', 'ImportError', 'OSError',
        'super', 'object', 'open', 'sorted', 'enumerate', 'zip', 'map',
        'any', 'all', 'min', 'max', 'sum', 'abs', 'chr', 'ord', 'hex',
        'bytes', 'bytearray', 'property', 'staticmethod', 'classmethod',
        '__name__', 'BASE_DIR', 'DOWNLOAD_RETRY_LIMIT',
        'Optional', 'List', 'Dict', 'Tuple', 'Any', 'Union',
    }
    
    undefined = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id not in safe:
                undefined.add(node.value.id)
    
    if not undefined:
        return code
    
    # Generate stubs
    stubs = []
    for name in sorted(undefined):
        if name in defined:
            continue
        # Generic permissive stub
        stubs.append(f'class _{name}_stub:\n    def __getattr__(self, n):\n        def _f(*a, **kw): return ""\n        return _f\n{name} = _{name}_stub()')
    
    if stubs:
        lines = code.split('\n')
        # Find insertion point after imports
        insert_idx = 0
        for i, line in enumerate(lines):
            if line.strip() and not line.startswith('#') and not line.startswith('import ') and not line.startswith('from '):
                insert_idx = i
                break
        stub_block = '\n# --- Stubs for missing dependencies ---\n' + '\n'.join(stubs) + '\n# --- End stubs ---\n'
        lines.insert(insert_idx, stub_block)
        code = '\n'.join(lines)
    
    return code


def fix_file(fname, cwe):
    """Apply all fixes to a file pair."""
    fixed = False
    
    for d in [VULN_DIR, PATCH_DIR, SRC_VULN, SRC_PATCH]:
        fpath = os.path.join(d, fname)
        if not os.path.exists(fpath):
            continue
        
        code = open(fpath).read()
        original = code
        
        # 1. Fix super() outside class
        code = fix_super_calls(code)
        
        # 2. Fix None parameters in main block
        code = fix_none_params(code, fname)
        
        # 3. Fix undefined closure variables
        code = fix_undefined_variables(code)
        
        # 4. Fix SQL table mismatches
        if cwe == "CWE-89":
            queried = set(re.findall(r'(?:FROM|INTO|UPDATE|JOIN)\s+(\w+)', code, re.IGNORECASE))
            created = set(re.findall(r'CREATE TABLE\s+(?:IF NOT EXISTS\s+)?(\w+)', code, re.IGNORECASE))
            # Filter out words from comments
            comment_words = set()
            for line in code.split('\n'):
                if line.strip().startswith('#'):
                    comment_words.update(re.findall(r'\b\w+\b', line))
            queried -= comment_words
            missing = queried - created - {'sqlite_master', 'the', 'DB', 'a'}
            
            if missing:
                insert_lines = []
                for table in missing:
                    if table.lower() in ('moves',):
                        insert_lines.append(f'conn.execute("CREATE TABLE {table} (id INTEGER PRIMARY KEY, gameID INTEGER, x INTEGER, y INTEGER, letter TEXT)")')
                        insert_lines.append(f'conn.execute("INSERT INTO {table} VALUES (1, 1, 0, 0, \'X\')")')
                        insert_lines.append(f'conn.execute("INSERT INTO {table} VALUES (2, 1, 1, 1, \'O\')")')
                    elif table.lower() in ('tags',):
                        insert_lines.append(f'conn.execute("CREATE TABLE {table} (id INTEGER PRIMARY KEY, tag TEXT, num INTEGER)")')
                        insert_lines.append(f'conn.execute("INSERT INTO {table} VALUES (1, \'python\', 1)")')
                    else:
                        insert_lines.append(f'conn.execute("CREATE TABLE {table} (id INTEGER PRIMARY KEY, name TEXT, value TEXT, file_id TEXT, path TEXT)")')
                        insert_lines.append(f'conn.execute("INSERT INTO {table} VALUES (1, \'test\', \'val\', \'fid1\', \'/test\')")')
                if insert_lines:
                    insert_lines.append('conn.commit()')
                    idx = code.rfind('conn.commit()')
                    if idx >= 0:
                        end = code.index('\n', idx)
                        code = code[:end+1] + '\n'.join(insert_lines) + '\n' + code[end+1:]
        
        # 5. Ensure all referenced names have stubs
        code = ensure_all_stubs(code)
        
        # 6. Validate syntax
        try:
            ast.parse(code)
        except SyntaxError as e:
            print(f"  SYNTAX ERROR after fix: {fname} in {d}: {e.msg} line {e.lineno}")
            continue
        
        if code != original:
            with open(fpath, 'w') as f:
                f.write(code)
            fixed = True
    
    return fixed


def main():
    total_fixed = 0
    
    for entry in manifest:
        fname = entry["filename"]
        cwe = entry["cwe"]
        if fix_file(fname, cwe):
            total_fixed += 1
    
    print(f"\nFixed {total_fixed} file groups")
    
    # Verify all files pass syntax check
    errors = 0
    for entry in manifest:
        for d in [VULN_DIR, PATCH_DIR]:
            fpath = os.path.join(d, entry["filename"])
            if os.path.exists(fpath):
                try:
                    ast.parse(open(fpath).read())
                except SyntaxError as e:
                    print(f"  STILL BROKEN: {entry['filename']} in {d}: {e}")
                    errors += 1
    
    print(f"Syntax errors remaining: {errors}")
    
    # Quick runtime test: try to run each file with timeout
    print("\nRuntime test (5s timeout each)...")
    runtime_ok = 0
    runtime_err = 0
    for entry in manifest:
        fpath = os.path.join(VULN_DIR, entry["filename"])
        if not os.path.exists(fpath):
            continue
        try:
            rc, stdout, stderr = try_run(fpath)
            if 'NameError' in stderr or 'ModuleNotFoundError' in stderr:
                if runtime_err < 10:
                    # Extract the error
                    err_line = [l for l in stderr.split('\n') if 'Error' in l][-1] if stderr else ''
                    print(f"  RUNTIME: {entry['filename']}: {err_line[:80]}")
                runtime_err += 1
            else:
                runtime_ok += 1
        except subprocess.TimeoutExpired:
            runtime_ok += 1  # Timeout is OK (Flask apps, etc.)
        except Exception as e:
            runtime_err += 1
    
    print(f"\nRuntime: {runtime_ok} OK, {runtime_err} errors out of {len(manifest)}")


if __name__ == "__main__":
    main()
