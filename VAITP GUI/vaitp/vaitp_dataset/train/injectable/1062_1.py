# Example of a vulnerable slice function in Vyper (not actual Vyper code)
def vulnerable_slice(array, start, length):
    return array[start:start + length]  # Vulnerable to overflow

# Example of a fixed slice function in Vyper
def safe_slice(array, start, length):
    if start < 0 or length < 0 or start + length > len(array):
        raise ValueError("Invalid slice parameters")
    return array[start:start + length]