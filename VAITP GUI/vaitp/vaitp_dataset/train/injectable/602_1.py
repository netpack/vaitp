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
            ast.Assign,
            ast.Call,
            ast.Attribute,
        }
        self.allowed_functions = {
            'abs',
            'all',
            'any',
            'bool',
            'chr',
            'complex',
            'dict',
            'divmod',
            'float',
            'frozenset',
            'int',
            'len',
            'list',
            'max',
            'min',
            'pow',
            'print',
            'range',
            'round',
            'set',
            'slice',
            'sorted',
            'str',
            'sum',
            'tuple',
        }
        self.allowed_attributes = {
            'real',
            'imag'
        }


    def is_safe(self, node):
        if isinstance(node, ast.Name):
            if node.id not in self.allowed_functions:
                raise ValueError(f"Unsafe name: {node.id}")
        elif isinstance(node, ast.Attribute):
             if not self.is_safe_attribute(node):
                raise ValueError(f"Unsafe attribute: {ast.unparse(node)}")

        elif type(node) not in self.allowed_nodes:
            raise ValueError(f"Unsafe node type: {type(node)}")

        for child in ast.iter_child_nodes(node):
            self.is_safe(child)

    def is_safe_attribute(self, attribute_node):
        if isinstance(attribute_node, ast.Attribute):
           if attribute_node.attr not in self.allowed_attributes:
              return False
           return self.is_safe_attribute(attribute_node.value)
        elif isinstance(attribute_node, ast.Name):
             if attribute_node.id not in self.allowed_functions:
                return False
             return True

        return False
    def safe_eval(self, code):
        try:
            tree = ast.parse(code, mode='eval')
        except SyntaxError as e:
            raise ValueError(f"Invalid syntax: {e}") from e
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