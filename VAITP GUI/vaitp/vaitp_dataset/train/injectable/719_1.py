import os
import subprocess
import tempfile
import ast

def safe_script_upload(script_content):
    if is_safe_script(script_content):
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as script_file:
            script_file.write(script_content.encode())
            script_path = script_file.name
        try:
            subprocess.run(['python3', script_path], check=True, capture_output=True, timeout=10)
        finally:
            os.remove(script_path)
    else:
        raise ValueError("Unsafe script content detected.")

def is_safe_script(script_content):
    try:
        tree = ast.parse(script_content)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom, ast.Call)):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in ['eval', 'exec', 'open']:
                        return False
                    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id in ['os', 'subprocess']:
                        return False
                else:
                    for alias in node.names:
                        if alias.name in ['os', 'subprocess']:
                             return False
        return True
    except SyntaxError:
        return False