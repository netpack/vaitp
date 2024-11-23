def lines_with_leading_tabs_expanded(input_string):
    lines = input_string.splitlines()
    expanded_lines = []

    for line in lines:
        leading_tabs = len(line) - len(line.lstrip('\t'))
        expanded_lines.append('\t' * leading_tabs + line.lstrip('\t'))

    return '\n'.join(expanded_lines)

# Example usage with a potentially malicious input
input_string = "\t" * 10000 + "This is a test line."
result = lines_with_leading_tabs_expanded(input_string)
print(result)