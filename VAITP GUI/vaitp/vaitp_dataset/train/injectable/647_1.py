import ast
import sys

def safe_eval(expr):
    # Restrict the eval to only allow certain safe expressions
    allowed_nodes = {
        ast.Expression,
        ast.Num,
        ast.Str,
        ast.List,
        ast.Tuple,
        ast.Name,
        ast.BinOp,
        ast.UnaryOp,
        ast.Load,
        ast.Store,
        ast.Call,
        ast.Attribute,
    }
    
    class SafeVisitor(ast.NodeVisitor):
        def visit(self, node):
            if type(node) not in allowed_nodes:
                raise ValueError("Unsafe operation detected.")
            return super().visit(node)

    tree = ast.parse(expr, mode='eval')
    SafeVisitor().visit(tree)
    
    # Evaluate the expression in a restricted environment
    return eval(compile(tree, filename="<ast>", mode="eval"), {"__builtins__": None}, {})

# Example usage
try:
    result = safe_eval("1 + 2")  # Safe expression
    print(result)
    
    # This would raise an error
    # result = safe_eval("__import__('os').system('ls')")  # Unsafe expression
except ValueError as e:
    print(e)