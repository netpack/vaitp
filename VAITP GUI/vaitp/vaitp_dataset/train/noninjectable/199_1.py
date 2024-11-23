def vulnerable_vsnprintf(format_string, *args):
    # This function does not properly handle input sizes, leading to potential overflows
    formatted_string = format_string % args
    # No length check, which can lead to memory issues
    return formatted_string

# Example usage
result = vulnerable_vsnprintf("%s" * 1000, *["A"] * 1000)
print(result)