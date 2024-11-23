import re

def safe_blame(input_string):
    # Using a more controlled regex to avoid catastrophic backtracking
    # This regex is simplified to avoid complex patterns that could lead to DoS
    pattern = re.compile(r'^[\w\s\-]+$')  # Allow only word characters, spaces, and hyphens

    if not pattern.match(input_string):
        raise ValueError("Input contains invalid characters")

    # Proceed with the blame functionality using the safe input
    # (Actual blame logic would go here)
    return "Blame processed for input: " + input_string

# Example usage
try:
    result = safe_blame("valid-input")
    print(result)
except ValueError as e:
    print(e)