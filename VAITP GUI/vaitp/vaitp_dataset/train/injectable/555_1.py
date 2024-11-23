# Example of a fix for CVE-2014-3593 by sanitizing input before evaluation

import ast

def safe_eval(user_input):
    # Only allow certain nodes in the AST
    allowed_nodes = {
        ast.Expression,
        ast.Num,
        ast.Str,
        ast.List,
        ast.Tuple,
        ast.Dict,
        ast.NameConstant,
        ast.UnaryOp,
        ast.BinOp,
        ast.Compare,
        ast.BoolOp,
        ast.IfExp,
        ast.Call,
        ast.Attribute,
        ast.Subscript,
    }

    # Parse the input into an AST
    tree = ast.parse(user_input, mode='eval')

    # Check if all nodes in the AST are allowed
    for node in ast.walk(tree):
        if type(node) not in allowed_nodes:
            raise ValueError("Unsafe expression")

    # Safely evaluate the sanitized AST
    return eval(compile(tree, filename='', mode='eval'))

# Example usage
try:
    result = safe_eval("2 + 2")  # Safe input
    print(result)
except ValueError as e:
    print(e)

try:
    result = safe_eval("__import__('os').system('ls')")  # Unsafe input
    print(result)
except ValueError as e:
    print(e)