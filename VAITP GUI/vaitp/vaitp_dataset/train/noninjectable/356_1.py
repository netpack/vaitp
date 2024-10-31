# Assumes an img HTML tag such as: <img alt="alt text" src="javascript:alert('XSS')">
import markdown2

# Unsafe Markdown input
markdown_input = "![alt text](javascript:alert('XSS'))"

# Rendering Markdown with safe_mode enabled
html_output = markdown2.markdown(markdown_input, extras=["safe-mode"])

print(html_output)