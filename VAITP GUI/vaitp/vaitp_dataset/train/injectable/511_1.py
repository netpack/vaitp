import ast

def safe_eval(expression):
    # Only allow specific nodes in the expression to prevent arbitrary code execution
    allowed_nodes = {
        ast.Expression,
        ast.BinOp,
        ast.UnaryOp,
        ast.Num,
        ast.Str,
        ast.Name,
        ast.Load,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.Mod,
        ast.Pow,
        ast.BitXor,
        ast.USub,
        ast.UAdd,
        ast.Compare,
        ast.Eq,
        ast.NotEq,
        ast.Lt,
        ast.LtE,
        ast.Gt,
        ast.GtE,
        ast.BoolOp,
        ast.And,
        ast.Or,
    }

    def _check_node(node):
        if type(node) not in allowed_nodes:
            raise ValueError("Disallowed expression")

    # Parse the expression and check for disallowed nodes
    tree = ast.parse(expression, mode='eval')
    for node in ast.walk(tree):
        _check_node(node)

    # Safely evaluate the expression
    return eval(compile(tree, filename='', mode='eval'))

# Example usage
user_input = "2 + 2"  # This should be a safe mathematical expression
result = safe_eval(user_input)
print(result)  # Output: 4