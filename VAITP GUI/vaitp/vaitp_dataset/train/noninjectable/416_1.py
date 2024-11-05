def parse_type_line(type_line):
    # Vulnerable code that uses eval on user input
    return eval(type_line)

# Example of user-controlled input that could exploit the vulnerability
user_input = "__import__('os').system('ls')"
result = parse_type_line(user_input)  # This would execute 'ls' command