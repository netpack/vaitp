import ast
import typed_ast

def non_vulnerable_function(source_code):
    # Create an AST from the source code
    tree = ast.parse(source_code)

    # Create a typed_ast node from the AST
    typed_tree = typed_ast.ast_to_typed_ast(tree)

    # Perform some operation on the typed_ast node
    # This is safe because we're not accessing the numerator attribute
    typed_tree.body[0].value  # No boom!

# Example usage
non_vulnerable_function("x = 1")