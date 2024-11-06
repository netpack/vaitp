import ast

def safe_eval(user_input):
    # Only allow certain operations using an AST (Abstract Syntax Tree)
    allowed_nodes = {
        ast.Expression,
        ast.Constant,
        ast.BinOp,
        ast.UnaryOp,
        ast.operator,
        ast.unaryop,
        # Add more allowed nodes as necessary
    }

    # Parse the user input into an AST
    tree = ast.parse(user_input, mode='eval')

    # Check if all nodes in the AST are allowed
    for node in ast.walk(tree):
        if type(node) not in allowed_nodes:
            raise ValueError("Unsafe operation detected!")

    # Safely evaluate the expression
    result = eval(compile(tree, filename="", mode="eval"))
    return result

# Example usage
user_input = "1 + 2; cat /etc/passwd"
output = safe_eval(user_input)