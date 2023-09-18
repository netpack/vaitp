from django.utils.safestring import mark_safe

# User input (simulating data from an untrusted source)
user_input = input()

# Using mark_safe without proper sanitization
html_output = mark_safe(user_input)

# Displaying the HTML output
print("HTML Output (Vulnerable):")
print(html_output)
