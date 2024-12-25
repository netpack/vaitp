# Example of sanitizing user input to prevent code execution vulnerabilities
import os

def sanitize_input(user_input):
    # Basic sanitization: remove potentially dangerous characters
    sanitized_input = user_input.replace(";", "").replace("'", "").replace("\"", "").replace("`", "")
    return sanitized_input

def execute_user_code(user_input):
    # Sanitize the user input before executing it
    safe_input = sanitize_input(user_input)
    
    # Example of executing code safely (this is just a representation)
    # In a real-world scenario, avoid executing user input directly
    try:
        # Here we would normally have a safe execution context
        # exec(safe_input)  # Dangerous if not sanitized properly
        print(f"Executing: {safe_input}") # Instead of executing we just print it to show
    except Exception as e:
        print(f"Error executing code: {e}")

# Example of user input that could be malicious
user_input = "print('Hello, World!'); os.system('rm -rf /')"  # Malicious input
execute_user_code(user_input)