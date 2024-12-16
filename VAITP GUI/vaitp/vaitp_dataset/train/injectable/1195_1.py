from lxml.html.clean import Cleaner

# Create a Cleaner object with settings to mitigate the vulnerability
cleaner = Cleaner(
    remove_tags=['svg', 'math', 'noscript'],  # Remove context-switching tags
    kill_tags=['script'],  # Completely remove script tags
    allow_tags=['p', 'div', 'span', 'a']  # Allow only safe tags
)

# Example of untrusted HTML input
html_input = """
<div>
    <style>
        /* This is a CSS comment */
    </style>
    <script>alert('XSS');</script>
    <svg><text>Malicious SVG content</text></svg>
    <math><msup><mi>x</mi><mn>2</mn></msup></math>
    <noscript>This should not be rendered</noscript>
    <p>Safe content</p>
</div>
"""

# Clean the HTML input
cleaned_html = cleaner.clean_html(html_input)

print(cleaned_html)