from lxml import html

# Example of vulnerable code prior to lxml 4.6.5
# This allows certain script content to pass through
vulnerable_input = '<div><script>alert("XSS")</script></div>'
cleaned_output = html.clean.clean_html(vulnerable_input)
print(cleaned_output)  # This may output the script tag, demonstrating the vulnerability