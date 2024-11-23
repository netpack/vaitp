import ast
import traceback

def safe_eval(expr):
    # Limit the allowed nodes in the AST to prevent unsafe operations
    allowed_nodes = {
        ast.Expression,
        ast.Num,
        ast.Str,
        ast.List,
        ast.Tuple,
        ast.Dict,
        ast.Name,
        ast.Load,
        ast.BinOp,
        ast.UnaryOp,
        ast.Compare,
        ast.BoolOp,
        ast.IfExp,
        ast.Call,
    }

    class SafeEvalVisitor(ast.NodeVisitor):
        def visit(self, node):
            if type(node) not in allowed_nodes:
                raise ValueError("Unsafe operation detected")
            return self.generic_visit(node)

    # Parse the expression into an AST
    tree = ast.parse(expr, mode='eval')

    # Check for allowed nodes
    SafeEvalVisitor().visit(tree)

    # Safely evaluate the expression
    return eval(compile(tree, filename="<ast>", mode="eval"))

# Example usage
try:
    user_input = "2 + 2"  # This should be controlled input
    result = safe_eval(user_input)
    print("Result:", result)
except Exception as e:
    print("Error:", traceback.format_exc())