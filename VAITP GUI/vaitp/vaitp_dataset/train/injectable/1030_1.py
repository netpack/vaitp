from mjml import mjml2html

# User input that could be malicious
user_input = "<script>alert('XSS');</script>"

# Create an MJML template with untrusted user input
mjml_template = f"""
<mjml>
  <mj-body>
    <mj-section>
      <mj-column>
        <mj-text>{user_input}</mj-text>
      </mj-column>
    </mj-section>
  </mj-body>
</mjml>
"""

# Render MJML to HTML (vulnerable to XSS if user_input is not sanitized)
html_output = mjml2html(mjml_template)

print(html_output)
```

To fix the vulnerability, ensure to sanitize user input before injecting it into the MJML template. Here’s an example of a simple sanitization function:

```python
import html

# Sanitize user input to prevent XSS
sanitized_input = html.escape(user_input)

# Create an MJML template with sanitized user input
mjml_template = f"""
<mjml>
  <mj-body>
    <mj-section>
      <mj-column>
        <mj-text>{sanitized_input}</mj-text>
      </mj-column>
    </mj-section>
  </mj-body>
</mjml>
"""

# Render MJML to HTML safely
html_output = mjml2html(mjml_template)

print(html_output)