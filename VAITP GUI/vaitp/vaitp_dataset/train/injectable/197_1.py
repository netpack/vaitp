def safe_expandtabs(input_string, tabsize):
    # Ensure tabsize is a non-negative integer and within a reasonable limit
    if not isinstance(tabsize, int) or tabsize < 0 or tabsize > 100:
        raise ValueError("tabsize must be a non-negative integer and less than or equal to 100")

    return input_string.expandtabs(tabsize)

# Example usage
try:
    result = safe_expandtabs("Hello\tWorld", 8)
    print(result)
except ValueError as e:
    print(e)