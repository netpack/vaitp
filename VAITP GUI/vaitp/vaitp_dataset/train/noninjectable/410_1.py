# Vulnerable code snippet (before patch)
from nbconvert import HTMLExporter

def convert_notebook_to_html(notebook_content):
    exporter = HTMLExporter()
    html_output, _ = exporter.from_notebook_node(notebook_content)
    return html_output

# Simulated user input (malicious content)
notebook_content = {
    'cells': [
        {
            'cell_type': 'code',
            'source': 'print("<script>alert(\'XSS Attack!\')</script>")'
        }
    ]
}

# This will include the malicious script in the output HTML
html_output = convert_notebook_to_html(notebook_content)
print(html_output)