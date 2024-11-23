import ujson

# Example of unsafe usage that could trigger the vulnerability
def unsafe_encode(data, indent):
    # No validation on the indent value
    return ujson.dumps(data, indent=indent)

# Example usage with excessive indentation
data = {"key": "value"}
encoded_data = unsafe_encode(data, indent=1000)  # Potentially dangerous
print(encoded_data)