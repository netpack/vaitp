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

# Render MJML to HTML (vulnerable to XSS)
html_output = mjml2html(mjml_template)

print(html_output)