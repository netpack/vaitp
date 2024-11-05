import pandas as pd

def create_csv(data):
    df = pd.DataFrame(data)
    # No sanitization of user input
    df.to_csv('output.csv', index=False)

# Example usage
user_input = [
    {"name": "Alice", "score": 90},
    {"name": "Bob", "score": "=cmd|' /C calc'!A0"}  # Malicious input
]

create_csv(user_input)