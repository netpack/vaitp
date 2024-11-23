import re

def vulnerable_blame(input_string):
    # Vulnerable regex that can lead to catastrophic backtracking
    pattern = re.compile(r'^(a+)+$')  # This pattern can cause excessive backtracking

    if not pattern.match(input_string):
        raise ValueError("Input does not match expected format")

    # Proceed with the blame functionality using the input
    # (Actual blame logic would go here)
    return "Blame processed for input: " + input_string

# Example usage
try:
    result = vulnerable_blame("a" * 10000 + "b")  # Malicious input to trigger DoS
    print(result)
except ValueError as e:
    print(e)