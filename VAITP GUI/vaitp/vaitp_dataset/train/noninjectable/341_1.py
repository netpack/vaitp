from markdown2 import markdown

def render_markdown(user_input):
    # This could lead to XSS if user_input contains malicious scripts
    html_output = markdown(user_input)
    return html_output

# Example of user input that could exploit the vulnerability
user_input = "<script>alert('XSS');</script>"
output = render_markdown(user_input)
print(output)  # This would execute the script when rendered in a browser