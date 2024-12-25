import ast

def load_rules(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    # Use ast.literal_eval to safely load the rules from a string representation of a Python literal
    try:
      rules = ast.literal_eval(content)
    except (ValueError, SyntaxError):
      raise ValueError("Invalid Python literal in rules file")
    return rules

# Example usage
# rules = load_rules('rules.mk')