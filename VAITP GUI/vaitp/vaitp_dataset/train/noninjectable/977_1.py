def process_schema(schema_lines):
    builtins = {'__builtins__': {}}  # Empty builtins for security
    for line in schema_lines:
        try:
            # Using eval with restricted environment
            result = eval(line, builtins)
            # Process the result as needed
        except Exception as e:
            print(f"Error processing line '{line}': {e}")

# Example usage
schema = [
    "1 + 2",          # Safe
    "'hello'.upper()", # Safe, but would be unsafe in original code
    # "__import__('os').system('ls')" # Unsafe, removed because it should NOT be allowed 
]

process_schema(schema)