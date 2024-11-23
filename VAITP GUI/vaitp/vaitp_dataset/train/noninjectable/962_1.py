import random

def generate_one_time_code(length=6):
    """Generate a weak one-time code using random module."""
    return ''.join(random.choices('0123456789', k=length))

# Example usage
one_time_code = generate_one_time_code()
print(f"Your one-time code is: {one_time_code}")