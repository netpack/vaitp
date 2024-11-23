import re

# Vulnerable regex pattern that can lead to ReDoS
def vulnerable_parse(input_string):
    # This regex can cause catastrophic backtracking
    pattern = re.compile(r'^(.*)([a-zA-Z0-9_]+)(.*)$')  # Unbounded repetition
    if pattern.match(input_string):
        return True
    else:
        raise ValueError("Input string is not valid.")

# Example usage
try:
    result = vulnerable_parse("a" * 10000 + "valid_input" + "b" * 10000)
    print("Input is valid:", result)
except ValueError as e:
    print(e)