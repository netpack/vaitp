from lxml.html.clean import Cleaner

# Create a Cleaner instance with safe_attrs_only and forms set to False
cleaner = Cleaner(safe_attrs_only=False, forms=False)

# Example of potentially malicious HTML input
malicious_html = '<form action="http://example.com" formaction="javascript:alert(\'XSS\')">Submit</form>'

# Clean the HTML input
cleaned_html = cleaner.clean_html(malicious_html)

print(cleaned_html)  # The formaction attribute may not be removed, allowing for XSS