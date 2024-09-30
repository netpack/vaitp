import ast
import typed_ast.ast3 as typed_ast

def vulnerable_function(source_code):
    # Create an AST from the source code
    tree = ast.parse(source_code)

    # Create a typed_ast node from the AST
    typed_tree = typed_ast.ast_to_typed_ast(tree)

    # Perform some operation on the typed_ast node
    # This is where the vulnerability is triggered
    typed_tree.body[0].value.numerator.numerator  # Boom!

# Example usage
vulnerable_function("x = 1")