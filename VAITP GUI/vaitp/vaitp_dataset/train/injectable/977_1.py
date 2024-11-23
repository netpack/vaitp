import ast

def safe_eval(expr):
    # Parse the expression into an AST node
    node = ast.parse(expr, mode='eval')

    # Ensure the expression only contains allowed nodes
    for n in ast.walk(node):
        if not isinstance(n, (ast.Expression, ast.Num, ast.Str, ast.List, ast.Dict, ast.Tuple, ast.Name, ast.BinOp, ast.UnaryOp, ast.Compare, ast.Call)):
            raise ValueError("Unsafe expression detected")

    # Safely evaluate the expression
    return eval(compile(node, '<string>', mode='eval'))

def process_schema(schema_lines):
    for line in schema_lines:
        try:
            # Use safe_eval instead of eval
            result = safe_eval(line)
            # Process the result as needed
        except Exception as e:
            print(f"Error processing line '{line}': {e}")

# Example usage
schema = [
    "1 + 2",          # Safe
    "'hello'.upper()", # Safe
    "__import__('os').system('ls')" # Unsafe, will raise an error
]

process_schema(schema)