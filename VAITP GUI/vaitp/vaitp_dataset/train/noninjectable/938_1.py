import math

def calculate_storage_slots(size_in_bytes):
    # Vulnerable calculation that can produce rounding errors
    return math.ceil(size_in_bytes / 32)

# Example usage
size_in_bytes = 2**46 - 1  # Example size that could trigger the vulnerability
slots_needed = calculate_storage_slots(size_in_bytes)
print(slots_needed)