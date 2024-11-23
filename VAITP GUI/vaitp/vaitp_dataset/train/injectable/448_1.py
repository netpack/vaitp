import ujson

def safe_encode(data, indent=None):
    # Validate the indent value to prevent excessive indentation
    if indent is not None and (indent < 0 or indent > 100):  # Example limit
        raise ValueError("Indentation level must be between 0 and 100.")
    
    return ujson.dumps(data, indent=indent)

# Example usage
data = {"key": "value"}
encoded_data = safe_encode(data, indent=4)
print(encoded_data)