from django.utils.html import escape

# User input (simulating data from an untrusted source)
user_input = input()

# Sanitize user input
sanitized_input = escape(user_input)

# Display the sanitized HTML output
print("Sanitized HTML Output (Safe):")
print(sanitized_input)
