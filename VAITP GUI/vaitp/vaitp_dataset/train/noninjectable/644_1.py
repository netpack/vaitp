def load_rules(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    # Use eval to load the rules, which allows execution of arbitrary Python code
    rules = eval(content)
    return rules

# Example usage
# rules = load_rules('rules.mk')