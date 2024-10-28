import mechanize, re

# Create a browser object
br = mechanize.Browser()

# This is a vulnerable regular expression pattern
# It can lead to catastrophic backtracking
vulnerable_regex = r'(a+)+$'

# Example of a payload that can cause ReDoS
# The input string is crafted to exploit the regex
malicious_input = 'a' * 1000 + 'b'  # This will cause excessive backtracking

# Attempt to match the vulnerable regex
try:
    if re.match(vulnerable_regex, malicious_input):
        print("Match found!")
    else:
        print("No match.")
except Exception as e:
    print(f"An error occurred: {e}")

# Use mechanize to open a URL
try:
    br.open("http://example.com")
except Exception as e:
    print(f"Failed to open URL: {e}")