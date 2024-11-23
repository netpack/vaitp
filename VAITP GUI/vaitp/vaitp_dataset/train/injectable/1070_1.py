from deepdiff import Delta

# Example of a safe deserialization process
def safe_deserialize(delta_serialized):
    # Implement a strict whitelist or validation for dunder attributes
    # This is a placeholder for actual validation logic
    def validate_delta(delta):
        for key in delta.keys():
            if key.startswith('__'):
                raise ValueError("Modification of dunder attributes is not allowed.")
    
    # Deserialize the delta and validate
    delta = Delta.from_dict(delta_serialized)
    validate_delta(delta)
    return delta

# Example usage
delta_serialized = {
    'some_attribute': 'new_value',
    '__dunder_attribute__': 'malicious_value'  # This should be caught by validation
}

try:
    safe_delta = safe_deserialize(delta_serialized)
except ValueError as e:
    print(e)  # Output: Modification of dunder attributes is not allowed.