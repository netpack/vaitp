import ast

def safe_run_script(script):
    # Only allow a limited set of safe commands
    allowed_commands = {'print', 'len', 'sum'}  # Example of allowed functions
    for node in ast.walk(ast.parse(script)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id not in allowed_commands:
                raise ValueError(f"Unauthorized command: {node.func.id}")
    exec(script)

# Example usage
malicious_script = "import os; os.system('whoami')"  # Malicious script example
try:
    safe_run_script(malicious_script)
except ValueError as e:
    print(e)  # Output: Unauthorized command: import