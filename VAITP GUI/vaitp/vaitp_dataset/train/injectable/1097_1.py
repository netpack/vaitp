def lines_with_leading_tabs_expanded(input_string):
    # Limit the number of leading tabs to prevent ReDoS
    max_leading_tabs = 100  # Set a reasonable limit
    lines = input_string.splitlines()
    expanded_lines = []

    for line in lines:
        leading_tabs = len(line) - len(line.lstrip('\t'))
        if leading_tabs > max_leading_tabs:
            leading_tabs = max_leading_tabs
        expanded_lines.append('\t' * leading_tabs + line.lstrip('\t'))

    return '\n'.join(expanded_lines)

# Example usage
input_string = "\t" * 1000 + "This is a test line."
result = lines_with_leading_tabs_expanded(input_string)
print(result)