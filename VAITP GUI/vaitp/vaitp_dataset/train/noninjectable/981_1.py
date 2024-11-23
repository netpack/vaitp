def unsafe_render(title):
    # This code is vulnerable to XSS as it directly inserts user input into the output
    return f"<div>{title}</div>"

# Example of how the function might be used
user_input = "<script>alert('XSS');</script>"
output = unsafe_render(user_input)
print(output)  # This would render the script tag and execute it in a browser