# Example of a fix for the CVE-2012-5485 vulnerability

def secure_eval(user_input):
    # Use a safe evaluation method instead of eval
    # For demonstration, we raise an error on unsafe input
    if not is_safe_input(user_input):
        raise ValueError("Unsafe input detected")

    # Process the safe input
    # This is where the actual logic would go
    # For example, if the input was a command, we would execute it safely
    return process_input(user_input)

def is_safe_input(user_input):
    # Implement checks to ensure the input is safe
    # For demonstration, we'll just allow alphanumeric characters
    return user_input.isalnum()

def process_input(user_input):
    # Placeholder for safe input processing logic
    print(f"Processing safe input: {user_input}")

# Example usage
try:
    user_input = "exampleCommand"  # This would be user-provided input
    secure_eval(user_input)
except ValueError as e:
    print(e)