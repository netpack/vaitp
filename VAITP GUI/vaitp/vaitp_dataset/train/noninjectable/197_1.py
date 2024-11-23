# Vulnerable code example demonstrating the issue with expandtabs
def vulnerable_expandtabs(input_string, tabsize):
    # No validation on tabsize, which can lead to integer overflow
    return input_string.expandtabs(tabsize)

# Example usage that could exploit the vulnerability
result = vulnerable_expandtabs("Hello\tWorld", 2**31)  # Large tabsize value
print(result)