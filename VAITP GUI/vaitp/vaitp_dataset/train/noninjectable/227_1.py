import python_libnmap

nmap = python_libnmap.Nmap()

# Vulnerable code: user_input is not validated
# The original code has two calls to nmap.scan, one with user_input
# and one without. The second call overwrites the first.
# Here we only use the user input after sanitizing it.
user_input = input("Enter a target to scan: ")

# Basic sanitization to prevent command injection.
# This is not foolproof and should be improved upon.
# Here we simply ensure the input string contains only allowed
# characters. For instance, letters, numbers, dots, hyphens and slashes.
allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-/"
sanitized_input = "".join(c for c in user_input if c in allowed_chars)

# The python-libnmap library expects targets, not generic commands.
# If the input is empty after sanitization then default target will be used.
if sanitized_input:
    nmap.scan(sanitized_input)
else:
    nmap.scan()


# Print the results
print(nmap.scan_result)