# Importing the necessary module from the Danijar Hafner definitions package
from definitions import load

# Example of a safe load function
def safe_load(input_data):
    # Validate the input data format before loading
    # Assuming the expected input is a JSON-like structure for demonstration
    if isinstance(input_data, dict):
        # Safely load the data without executing arbitrary code
        return load(input_data)
    else:
        raise ValueError("Invalid input data format. Expected a dictionary.")

# Simulating safe input that adheres to the expected format
safe_input = {
    "key": "value",
    "another_key": "another_value"
}

# Calling the safe function with valid input
try:
    result = safe_load(safe_input)
    print("Loaded data:", result)
except ValueError as e:
    print("Error:", e)