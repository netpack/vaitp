#!/usr/bin/env python3
"""
Fix runtime issues in SVEN+PyVul dataset files.
Scans each file for undefined references and injects stubs/imports.
"""
import ast
import os
import re
import json

DIRS = [
    "vaitp_dataset/phase3_sven_pyvul/vulnerable",
    "vaitp_dataset/phase3_sven_pyvul/injectable",
    "vaitp_dataset/vulnerable",
    "vaitp_dataset/injectable",
]
MANIFEST = "vaitp_dataset/phase3_sven_pyvul/manifest.json"

# Known safe names that don't need stubs
SAFE_NAMES = {
    'os', 'sys', 'subprocess', 'json', 'base64', 'pickle', 'yaml', 're',
    'sqlite3', 'io', 'tempfile', 'shutil', 'hashlib', 'secrets', 'math',
    'time', 'datetime', 'collections', 'functools', 'itertools',
    'flask', 'Flask', 'request', 'session', 'redirect', 'url_for',
    'flash', 'abort', 'jsonify', 'make_response', 'g',
    'app', 'conn', 'user_input', 'raw', 'url', 'result', 'e', 'f',
    'requests', 'req_lib', 'urllib',
    # Python builtins
    'print', 'input', 'len', 'range', 'str', 'int', 'float', 'bool',
    'list', 'dict', 'set', 'tuple', 'type', 'isinstance', 'issubclass',
    'hasattr', 'getattr', 'setattr', 'delattr', 'property',
    'True', 'False', 'None', 'Exception', 'ValueError', 'TypeError',
    'KeyError', 'IndexError', 'AttributeError', 'RuntimeError',
    'NotImplementedError', 'StopIteration', 'OSError', 'IOError',
    'FileNotFoundError', 'PermissionError', 'ImportError',
    'super', 'object', 'staticmethod', 'classmethod', 'property',
    'open', 'sorted', 'reversed', 'enumerate', 'zip', 'map', 'filter',
    'any', 'all', 'min', 'max', 'sum', 'abs', 'round', 'chr', 'ord',
    'hex', 'oct', 'bin', 'id', 'hash', 'repr', 'format', 'vars', 'dir',
    'globals', 'locals', 'callable', 'iter', 'next', 'bytes', 'bytearray',
    'memoryview', 'complex', 'frozenset', 'slice', 'Ellipsis',
    'NotImplemented', 'breakpoint', 'compile', 'eval', 'exec',
    '__name__', '__main__', '__file__', '__doc__',
    'Optional', 'List', 'Dict', 'Tuple', 'Any', 'Union', 'Set',
    'Callable', 'Iterator', 'Iterable', 'Mapping', 'Sequence', 'Type',
    'BASE_DIR',
}

# Modules that just need an import statement
IMPORTABLE = {
    'logging', 'traceback', 'ipaddress', 'textwrap', 'unicodedata',
    'argparse', 'copy', 'fnmatch', 'glob', 'string', 'struct',
    'binascii', 'codecs', 'csv', 'pathlib', 'typing', 'abc',
    'xml', 'html', 'http', 'socket', 'ssl', 'threading',
    'multiprocessing', 'signal', 'errno', 'stat', 'random',
    'warnings', 'contextlib', 'dataclasses',
}


def find_undefined_attrs(code):
    """Find all obj.attr references where obj is not defined/imported."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return set()

    # Collect all defined/imported names
    defined = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                defined.add(alias.asname or alias.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                defined.add(node.module.split('.')[0])
            for alias in node.names:
                defined.add(alias.asname or alias.name)
        elif isinstance(node, ast.FunctionDef):
            defined.add(node.name)
            for arg in node.args.args:
                defined.add(arg.arg)
        elif isinstance(node, ast.ClassDef):
            defined.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    defined.add(t.id)
        elif isinstance(node, ast.For):
            if isinstance(node.target, ast.Name):
                defined.add(node.target.id)
        elif isinstance(node, ast.With):
            for item in node.items:
                if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                    defined.add(item.optional_vars.id)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                defined.add(node.name)
        elif isinstance(node, ast.Global):
            for name in node.names:
                defined.add(name)
        elif isinstance(node, ast.comprehension):
            if isinstance(node.target, ast.Name):
                defined.add(node.target.id)
            elif isinstance(node.target, ast.Tuple):
                for elt in node.target.elts:
                    if isinstance(elt, ast.Name):
                        defined.add(elt.id)

    # Find undefined obj.attr references
    undefined = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            obj = node.value.id
            if obj not in defined and obj not in SAFE_NAMES:
                undefined.add(obj)

    return undefined


def generate_stubs(undefined_names, code):
    """Generate stub code for undefined names."""
    stubs = []
    already_handled = set()

    for name in sorted(undefined_names):
        if name in already_handled:
            continue

        # Check if it's a standard library module
        if name in IMPORTABLE:
            stubs.append(f"import {name}")
            already_handled.add(name)
            continue

        # Known stubs for common patterns
        known_stubs = {
            'utils': 'import subprocess\nclass utils:\n    @staticmethod\n    def execute(*args, process_input=None, run_as_root=False):\n        cmd = list(args)\n        if process_input:\n            subprocess.run(cmd, input=process_input.encode() if isinstance(process_input, str) else process_input)\n        else:\n            subprocess.run(cmd)',
            'logger': 'import logging\nlogger = logging.getLogger(__name__)',
            'LOGGER': 'import logging\nLOGGER = logging.getLogger(__name__)',
            'exceptions': 'class exceptions:\n    class ValidationError(Exception): pass',
            'common': 'class common:\n    @staticmethod\n    def _cli_run(*args, **kwargs): return "", ""',
            'sql': 'class sql:\n    @staticmethod\n    def queryDB(query, params=None): return []',
            'api': 'class api:\n    @staticmethod\n    def route(*a, **kw): return lambda f: f',
            'objreg': 'class objreg:\n    @staticmethod\n    def get(*a, **kw): return type("O", (), {"data": lambda s: []})()',
            'register': 'class register:\n    @staticmethod\n    def tag(*a, **kw): return lambda f: f',
            'config': 'class config:\n    key_servers = []\n    @staticmethod\n    def retrieveBoilerplateFile(*a, **kw): return ""',
            'settings': 'class settings:\n    STATIC_URL = "/static/"\n    MEDIA_URL = "/media/"',
            'current_app': 'class current_app:\n    config = {"SERVER_NAME": "localhost", "PREFERRED_URL_SCHEME": "http"}',
            'core': 'import json as _json\nclass core:\n    @staticmethod\n    def parse_json(data): return _json.loads(data)',
            'catalog_api': 'class catalog_api:\n    @staticmethod\n    def get_service(*a, **kw): return {}\n    @staticmethod\n    def list_services(*a, **kw): return []',
            'identity_api': 'class identity_api:\n    @staticmethod\n    def get_user(*a, **kw): return {}',
            'OneLogin_Saml2_ValidationError': 'class OneLogin_Saml2_ValidationError(Exception):\n    DUPLICATED_ATTRIBUTE_NAME_FOUND = "Duplicated attribute"',
            'OneLogin_Saml2_Utils': 'class OneLogin_Saml2_Utils:\n    @staticmethod\n    def query(dom, expr, ctx=None): return []',
            'hostname_regex': 'import re\nhostname_regex = re.compile(r"^[a-zA-Z0-9._-]+$")',
            'media_file_manager': 'class media_file_manager:\n    @staticmethod\n    def get(*a, **kw): return type("O", (), {"is_relative_to": lambda s, p: True})()',
            'FieldInfo': 'class FieldInfo:\n    @staticmethod\n    def factory(*a, **kw): return {}',
            'PREFECT_UNIT_TEST_MODE': 'class PREFECT_UNIT_TEST_MODE:\n    @staticmethod\n    def value(): return False',
            '_rpc': 'class _rpc:\n    @staticmethod\n    def update(*a, **kw): pass',
            'cookiejar': 'class cookiejar:\n    @staticmethod\n    def get_cookie_header(*a, **kw): return ""',
            'Template': 'class Template:\n    def __init__(self, s=""): self.s = s\n    def render(self, **kw): return self.s',
            'simplejson': 'import json as simplejson',
            'regex': 'import re as regex',
            'pa': 'class pa:\n    class Table:\n        @staticmethod\n        def from_pandas(*a, **kw): return None',
            'node': 'class node:\n    text = ""',
        }

        if name in known_stubs:
            stubs.append(known_stubs[name])
            already_handled.add(name)
        else:
            # Generic stub: create a permissive mock object
            stubs.append(f'class {name}:\n    def __getattr__(self, n): return lambda *a, **kw: None\n{name} = {name}()')
            already_handled.add(name)

    return '\n'.join(stubs)


def fix_sql_schema(code):
    """Fix SQL schema mismatches."""
    queried = set(re.findall(r'(?:FROM|INTO|UPDATE|JOIN)\s+(\w+)', code, re.IGNORECASE))
    created = set(re.findall(r'CREATE TABLE\s+(?:IF NOT EXISTS\s+)?(\w+)', code, re.IGNORECASE))
    missing = queried - created - {'sqlite_master'}
    if not missing:
        return code

    schemas = {
        'moves': ('CREATE TABLE moves (id INTEGER PRIMARY KEY, gameID INTEGER, x INTEGER, y INTEGER, letter TEXT)',
                  'INSERT INTO moves VALUES (1, 1, 0, 0, \'X\')',
                  'INSERT INTO moves VALUES (2, 1, 1, 1, \'O\')'),
        'tags': ('CREATE TABLE tags (id INTEGER PRIMARY KEY, tag TEXT, num INTEGER)',
                 'INSERT INTO tags VALUES (1, \'python\', 1)'),
        'tbldbcitem': ('CREATE TABLE tbldbcitem (id INTEGER PRIMARY KEY, name TEXT, value TEXT, column_name TEXT)',
                       'INSERT INTO tbldbcitem VALUES (1, \'test\', \'val\', \'col\')'),
        'posts': ('CREATE TABLE posts (id INTEGER PRIMARY KEY, postid TEXT, title TEXT, content TEXT)',
                  'INSERT INTO posts VALUES (1, \'1\', \'Test\', \'Content\')'),
    }

    insert_lines = []
    for table in missing:
        if table.lower() in schemas:
            for stmt in schemas[table.lower()]:
                insert_lines.append(f'conn.execute("{stmt}")')
        else:
            insert_lines.append(f'conn.execute("CREATE TABLE {table} (id INTEGER PRIMARY KEY, name TEXT, value TEXT)")')
    insert_lines.append('conn.commit()')

    # Insert after last conn.commit()
    idx = code.rfind('conn.commit()')
    if idx >= 0:
        end = code.index('\n', idx)
        code = code[:end+1] + '\n'.join(insert_lines) + '\n' + code[end+1:]
    return code


def fix_file(fpath, cwe):
    """Fix a single file."""
    code = open(fpath).read()
    original = code

    # Fix SQL schemas first
    if cwe == "CWE-89":
        code = fix_sql_schema(code)

    # Fix None params in main block
    code = code.replace('build_board(conn, user_input, None)', 'build_board(conn, user_input, 3)')

    # Find undefined references
    undefined = find_undefined_attrs(code)
    if undefined:
        stubs = generate_stubs(undefined, code)
        if stubs:
            # Insert stubs after the last import line
            lines = code.split('\n')
            insert_idx = 0
            for i, line in enumerate(lines):
                if line.startswith('import ') or line.startswith('from ') or line.startswith('class ') and i < 5:
                    insert_idx = i + 1
            # Find the end of the import block
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped and not stripped.startswith('#') and not stripped.startswith('import ') and not stripped.startswith('from '):
                    insert_idx = i
                    break
            lines.insert(insert_idx, '\n# --- Auto-generated stubs for missing dependencies ---\n' + stubs + '\n# --- End stubs ---\n')
            code = '\n'.join(lines)

    # Validate
    try:
        ast.parse(code)
    except SyntaxError as e:
        print(f"  WARN: {os.path.basename(fpath)} syntax error after fix: {e.msg} line {e.lineno}")
        return False

    if code != original:
        with open(fpath, 'w') as f:
            f.write(code)
        return True
    return False


def main():
    manifest = json.load(open(MANIFEST))
    fixed_count = 0

    for entry in manifest:
        fname = entry["filename"]
        cwe = entry["cwe"]
        for d in DIRS:
            fpath = os.path.join(d, fname)
            if os.path.exists(fpath):
                if fix_file(fpath, cwe):
                    fixed_count += 1

    print(f"Fixed {fixed_count} files")

    # Re-check
    issues = 0
    for entry in manifest:
        fpath = os.path.join("vaitp_dataset/vulnerable", entry["filename"])
        if os.path.exists(fpath):
            code = open(fpath).read()
            undef = find_undefined_attrs(code)
            if undef:
                issues += 1
                if issues <= 5:
                    print(f"  Still has issues: {entry['filename']}: {undef}")

    print(f"Remaining files with undefined refs: {issues}/100")


if __name__ == "__main__":
    main()
