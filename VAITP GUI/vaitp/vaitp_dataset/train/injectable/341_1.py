from markdown2 import markdown
import html

def render_markdown(user_input):
    # Escape user input to prevent XSS
    escaped_input = html.escape(user_input)
    html_output = markdown(escaped_input)
    return html_output

# Example of user input that could exploit the vulnerability
user_input = "<script>alert('XSS');</script>"
output = render_markdown(user_input)
print(output)  # This will output &lt;script&gt;alert('XSS');&lt;/script&gt; safely