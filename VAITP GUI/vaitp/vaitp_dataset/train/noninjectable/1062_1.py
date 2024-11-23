# Example of a vulnerable slice function in Vyper (not actual Vyper code)
def vulnerable_slice(array, start, length):
    return array[start:start + length]  # Vulnerable to overflow