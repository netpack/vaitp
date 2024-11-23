from lxml import html
from lxml.html.clean import Cleaner

# Create a Cleaner instance without proper sanitization settings
cleaner = Cleaner(
    scripts=False,  # Disallow scripts (vulnerability)
    javascript=False,  # Disallow javascript (vulnerability)
    comments=True,
    style=True,
    links=True,
    meta=True,
    page_structure=True,
    remove_unknown_tags=False,
    safe_attrs_only=False,  # Allow unsafe attributes (vulnerability)
)

# Sample potentially malicious input
malicious_input = '<div><script>alert("XSS Attack!");</script></div>'

# Sanitize the input
sanitized_output = cleaner.clean_html(malicious_input)

print(sanitized_output)  # This may output the malicious script without proper sanitization