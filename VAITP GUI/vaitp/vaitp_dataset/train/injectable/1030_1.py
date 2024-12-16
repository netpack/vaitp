import html

# User input that could be malicious
user_input = "<script>alert('XSS');</script>"

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