import ast

def safe_load_rules(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    # Use ast.literal_eval to safely evaluate the content
    try:
        rules = ast.literal_eval(content)
    except (SyntaxError, ValueError):
        raise ValueError("Invalid rules format")
    return rules

# Example usage
# rules = safe_load_rules('rules.mk')