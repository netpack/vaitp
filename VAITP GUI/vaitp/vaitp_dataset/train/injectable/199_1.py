def safe_vsnprintf(format_string, *args):
    # Limit the maximum length of the formatted string to prevent overflow
    MAX_LENGTH = 1024
    formatted_string = format_string % args
    
    if len(formatted_string) > MAX_LENGTH:
        raise ValueError("Formatted string exceeds maximum length")
    
    return formatted_string

# Example usage
try:
    result = safe_vsnprintf("Hello, %s!", "World")
    print(result)
except ValueError as e:
    print(e)