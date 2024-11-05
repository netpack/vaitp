def parse_type_line(type_line):
    # Patched code that does not use eval on user input
    # Instead, we would validate the type_line or use safe parsing
    if not is_safe_input(type_line):
        raise ValueError("Unsafe input detected.")
    # Further processing of type_line
    return type_line  # This is just a placeholder for actual processing

def is_safe_input(type_line):
    # Implement validation logic here
    # For example, check against a whitelist of allowed types
    allowed_types = ['int', 'float', 'str', 'list', 'dict']
    return any(type_line.startswith(allowed_type) for allowed_type in allowed_types)

# Example of user input
user_input = "int"
result = parse_type_line(user_input)  # This would be processed safely