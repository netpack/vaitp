import markdown2
from markdown2 import Markdown

# User input that could contain malicious scripts
user_input = "<script>alert('XSS');</script>"

# Creating a Markdown instance with safe options
markdowner = Markdown(extras=["safe-mode"])

# Rendering user input as HTML with proper escaping
html_output = markdowner.convert(user_input)

print(html_output)  # This would escape the script tags, rendering them harmless