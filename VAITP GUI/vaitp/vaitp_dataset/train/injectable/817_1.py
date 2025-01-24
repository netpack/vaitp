import ast

def safe_execute_code(user_input):
    try:
        tree = ast.parse(user_input)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom, ast.Call, ast.Attribute)):
                if isinstance(node, ast.Call):
                   if isinstance(node.func, ast.Name) and node.func.id in ['exec', 'eval']:
                        raise ValueError("Function call is not allowed")

                elif isinstance(node, ast.Attribute):
                    if isinstance(node.value, ast.Name) and node.value.id == '__builtins__':
                        raise ValueError("Access to __builtins__ is not allowed.")
                    if isinstance(node.value, ast.Name) and node.value.id in ['os', 'sys', 'subprocess']:
                        raise ValueError("Access to os/sys/subprocess is not allowed.")
                else:
                    raise ValueError("Import statements are not allowed.")

        compiled_code = compile(tree, filename="<string>", mode="exec")
        local_env = {}
        exec(compiled_code, {}, local_env)
    except Exception as e:
        print(f"Error executing code: {e}")
