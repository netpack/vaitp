from lxml import html
from lxml.html.clean import Cleaner

# Create a Cleaner instance with proper sanitization settings
cleaner = Cleaner(
    scripts=True,  # Remove scripts
    javascript=True,  # Remove javascript
    comments=True,
    style=True,
    links=True,
    meta=True,
    page_structure=True,
    remove_unknown_tags=False,
    safe_attrs_only=True,  # Allow only safe attributes
)

# Sample potentially malicious input
malicious_input = '<div><script>alert("XSS Attack!");</script></div>'

# Sanitize the input
sanitized_output = cleaner.clean_html(malicious_input)

print(sanitized_output)