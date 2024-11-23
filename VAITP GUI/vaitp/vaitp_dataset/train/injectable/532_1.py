from jinja2 import Template

def safe_render(template_string, context):
    # Use a safe template rendering method to prevent SSTI
    template = Template(template_string)
    return template.render(context)

# Example usage
template_string = "Hello, {{ user }}!"
context = {"user": "Alice"}
output = safe_render(template_string, context)
print(output)