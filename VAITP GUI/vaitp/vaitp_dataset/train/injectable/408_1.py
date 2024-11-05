import pandas as pd

def sanitize_value(value):
    # Sanitize the value to prevent formula injection
    if isinstance(value, str) and value.startswith(('=', '+', '-', '@')):
        return "'" + value  # Prepend a single quote to neutralize the formula
    return value

def create_csv(data):
    sanitized_data = [{k: sanitize_value(v) for k, v in row.items()} for row in data]
    df = pd.DataFrame(sanitized_data)
    df.to_csv('output.csv', index=False)

# Example usage
user_input = [
    {"name": "Alice", "score": 90},
    {"name": "Bob", "score": "=cmd|' /C calc'!A0"}  # Malicious input
]

create_csv(user_input)