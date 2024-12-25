# Example demonstrating the vulnerability CVE-2023-40015 in Vyper-like behavior

# Simulated state
state = {"value": 0}

def side_effect_function():
    state["value"] += 1
    return state["value"]

def safe_expression(arg1, arg2):
    # Ensure no side effects are present in the arguments
    return arg1 + arg2

def unsafe_add(arg1, arg2):
    return arg1 + arg2

# Vulnerable usage
result = unsafe_add(side_effect_function(), 5)  # This can lead to unexpected behavior

# Fixed usage
# Avoid using side-effect producing functions directly in expressions
side_effect_result = side_effect_function()
result = safe_expression(side_effect_result, 5)  # Safe as side effects are evaluated first