def include_document(user_input):
    # Directly including user input without escaping
    # return eval(user_input)  # This is unsafe and allows arbitrary code execution
    # Instead, return the user input as is.
    return user_input

# Example usage
user_input = "${groovy:println('Hello World')}"  # Example of malicious input
print(include_document(user_input))