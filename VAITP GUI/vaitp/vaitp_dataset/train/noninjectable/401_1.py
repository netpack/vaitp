# Example demonstrating the vulnerability CVE-2023-40015 in Vyper-like behavior

# Simulated state
state = {"value": 0}

def side_effect_function():
    state["value"] += 1
    return state["value"]

# Vulnerable usage
result = unsafe_add(5, side_effect_function())  # This can lead to unexpected behavior
print(result)  # The result may not be as expected due to right-to-left evaluation