from lxml import html
from lxml.html.clean import Cleaner

# Create a Cleaner instance with safe settings
cleaner = Cleaner(
    scripts=True,  # Allow scripts (to be sanitized)
    javascript=True,  # Allow javascript (to be sanitized)
    comments=True,  # Allow comments (to be sanitized)
    style=True,  # Allow style (to be sanitized)
    links=True,  # Allow links (to be sanitized)
    meta=True,  # Allow meta tags (to be sanitized)
    page_structure=True,  # Ensure page structure is maintained
    remove_unknown_tags=False,  # Do not remove unknown tags
    safe_attrs_only=True,  # Only allow safe attributes
)

# Sample potentially malicious input
malicious_input = '<div><script>alert("XSS Attack!");</script></div>'

# Sanitize the input
sanitized_output = cleaner.clean_html(malicious_input)

print(sanitized_output)