def math_command(expression):
    # Vulnerable code using eval
    result = eval(expression)
    return result

# Example usage in the /math command
user_input = "2 + 2"  # This could be manipulated by an attacker
print(math_command(user_input))