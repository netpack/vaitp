import ast
import sys

class SafeEval:
    def __init__(self):
        self.allowed_nodes = {
            ast.Expression,
            ast.BinOp,
            ast.UnaryOp,
            ast.Num,
            ast.Str,
            ast.List,
            ast.Tuple,
            ast.Name,
            ast.Load,
            ast.Store,
            ast.Assign,
            ast.Call,
            ast.Attribute,
            ast.FunctionDef,
            ast.arguments,
            ast.arg,
        }

    def is_safe(self, node):
        if type(node) not in self.allowed_nodes:
            raise ValueError("Unsafe node type: {}".format(type(node)))
        for child in ast.iter_child_nodes(node):
            self.is_safe(child)

    def safe_eval(self, code):
        tree = ast.parse(code, mode='eval')
        self.is_safe(tree)
        return eval(compile(tree, filename="<ast>", mode="eval"))

# Example of usage
if __name__ == "__main__":
    safe_eval = SafeEval()
    user_input = input("Enter your Python code: ")
    try:
        result = safe_eval.safe_eval(user_input)
        print("Result:", result)
    except Exception as e:
        print("Error:", e)