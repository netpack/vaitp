from lxml import html

# Example of potentially vulnerable code prior to lxml 4.6.5
# This may allow certain script content to pass through
vulnerable_input = '<div><script>alert("XSS")</script></div>'
cleaned_output = html.clean.clean_html(vulnerable_input)
print(cleaned_output)

# Fixed code using lxml 4.6.5 or later
# This will properly sanitize the input and block the script content
from lxml.html import clean

cleaner = clean.Cleaner(safe_attrs_only=True)
fixed_output = cleaner.clean_html(vulnerable_input)
print(fixed_output)