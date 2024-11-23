# Vulnerable code that includes the potentially malicious democritus-html package
# from the d8s-asns package version 0.1.0.

import democritus_html  # This is the vulnerable package

def render_html(content):
    # Using the vulnerable package to render HTML
    return democritus_html.render(content)

# Example usage
html_content = render_html("Hello, world!")
print(html_content)