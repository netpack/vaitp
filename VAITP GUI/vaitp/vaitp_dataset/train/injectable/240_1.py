import mechanize, re

# Create a browser object
br = mechanize.Browser()

# A safe regular expression pattern
# This pattern matches a string of 'a's followed by the end of the string
safe_regex = r'^a+$'

# Example input that is safe to match against
input_string = 'a' * 1000  # This input is safe as it matches the regex

# Attempt to match the safe regex
try:
    if re.match(safe_regex, input_string):
        print("Match found!")
    else:
        print("No match.")
except Exception as e:
    print(f"An error occurred: {e}")

# Use mechanize to open a URL
try:
    response = br.open("http://example.com")
    print("Successfully opened URL:", response.geturl())
except Exception as e:
    print(f"Failed to open URL: {e}")