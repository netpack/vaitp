# Example of fixing the sandboxing issue in Odoo

import ast
import logging

# Create a safe environment for the code execution
def safe_exec(code, globals=None, locals=None):
    # Restrict the available built-ins and functions
    safe_builtins = {
        'print': print,
        # Add other safe built-ins as needed
    }
    
    # Create a restricted environment
    if globals is None:
        globals = {}
    if locals is None:
        locals = {}

    # Use ast.literal_eval to safely evaluate expressions
    try:
        # Only allow safe expressions to be executed
        code_ast = ast.parse(code, mode='exec')
        for node in ast.walk(code_ast):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                raise ValueError("Imports are not allowed.")
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                     if node.func.id not in safe_builtins:
                        raise ValueError("Unsafe function call detected.")
                else:
                    raise ValueError("Unsafe function call detected.")
        
        exec(compile(code_ast, filename="<ast>", mode="exec"), {**globals, **safe_builtins}, locals)
    except Exception as e:
        logging.error(f"Error executing code: {e}")

# Example usage
user_code = "print('Hello, World!')"  # This is user-provided code
safe_exec(user_code)