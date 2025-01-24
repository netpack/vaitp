from lxml.html import clean

# Example of potentially vulnerable code prior to lxml 4.6.5
# This may allow certain script content to pass through
vulnerable_input = '<div><script>alert("XSS")</script></div>'


# Fixed code using lxml 4.6.5 or later
# This will properly sanitize the input and block the script content

cleaner = clean.Cleaner(safe_attrs_only=True, scripts=True, javascript=True, style=True, links=True, meta=True, embedded=True, forms=True, frames=True, add_nofollow=True, host_whitelist=[])
fixed_output = cleaner.clean_html(vulnerable_input)
print(fixed_output)