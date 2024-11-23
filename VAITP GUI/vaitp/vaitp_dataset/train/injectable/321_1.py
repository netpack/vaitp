# Fixed version of the d8s-timer package that avoids executing arbitrary code
def safe_function(data):
    # Validate input to prevent code execution vulnerabilities
    if isinstance(data, str) and data.isalnum():
        return f"Processed data: {data}"
    else:
        raise ValueError("Invalid input data")

# Example usage
try:
    result = safe_function("validInput123")
    print(result)
except ValueError as e:
    print(e)