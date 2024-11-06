import markdown2

# User input that could contain malicious scripts
user_input = "<script>alert('XSS');</script>"

# Rendering user input as HTML without proper escaping
html_output = markdown2.markdown(user_input)

print(html_output)  # This would render the script and execute it in the browser