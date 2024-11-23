import ast

def safe_eval(expr):
    # Use ast.literal_eval to safely evaluate expressions
    return ast.literal_eval(expr)

def import_bvh(file_path):
    with open(file_path, 'r') as file:
        # Assuming the file is read and parsed into a hierarchy element
        hierarchy_element = file.read()  # Placeholder for actual parsing logic
        
        # Instead of eval, use safe_eval
        try:
            result = safe_eval(hierarchy_element)
            # Continue processing with the result
        except (ValueError, SyntaxError) as e:
            print(f"Error processing the hierarchy element: {e}")