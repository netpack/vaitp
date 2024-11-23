import secrets

def generate_one_time_code(length=6):
    """Generate a cryptographically secure one-time code."""
    return ''.join(secrets.choice('0123456789') for _ in range(length))

# Example usage
one_time_code = generate_one_time_code()
print(f"Your one-time code is: {one_time_code}")