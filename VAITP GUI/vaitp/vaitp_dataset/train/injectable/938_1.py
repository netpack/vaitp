import math

def calculate_storage_slots(size_in_bytes):
    # Fixed calculation to avoid floating point rounding errors
    return (size_in_bytes + 31) // 32  # Using integer division to ensure correct slot count

# Example usage
size_in_bytes = 2**46 - 1  # Example size that could trigger the vulnerability
slots_needed = calculate_storage_slots(size_in_bytes)
print(slots_needed)