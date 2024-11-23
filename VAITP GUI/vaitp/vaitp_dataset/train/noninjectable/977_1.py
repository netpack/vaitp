def process_schema(schema_lines):
    builtins = {'__builtins__': {'print': print}}  # Limited builtins for protection
    for line in schema_lines:
        try:
            # Using eval directly on schema lines
            result = eval(line, builtins)
            # Process the result as needed
        except Exception as e:
            print(f"Error processing line '{line}': {e}")

# Example usage
schema = [
    "1 + 2",          # Safe
    "'hello'.upper()", # Safe
    "__import__('os').system('ls')" # Unsafe, can execute system commands
]

process_schema(schema)