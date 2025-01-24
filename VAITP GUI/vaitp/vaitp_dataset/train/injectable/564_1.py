import logging
import ast

logging.basicConfig(level=logging.INFO)

def execute_code(code, user_token):
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom, ast.Call, ast.Attribute)):
                logging.warning("Potentially unsafe operation detected in user code: %s", ast.unparse(node))
                return
        
        compiled_code = compile(tree, filename="<string>", mode="exec")
        
        # Execute the user-provided code safely within a restricted environment
        local_env = {'__builtins__': {}}
        exec(compiled_code, local_env)
    except Exception as e:
        logging.error("An error occurred while executing code: %s", e)

user_code = "print('Hello, World!')"
user_token = "sensitive_token_here"
execute_code(user_code, user_token)
