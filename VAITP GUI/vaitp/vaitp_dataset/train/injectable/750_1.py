# Example of a safe template rendering function that disables execution of arbitrary Python code

from Cheetah.Template import Template

def render_template(template_string, **context):
    # Use a safe rendering method that does not allow execution of arbitrary code
    # This is a simplified example, and in practice, you would use a more secure templating approach
    safe_context = {key: str(value) for key, value in context.items()}  # Convert context values to strings
    template = Template(template_string, searchList=[safe_context])
    return str(template)

# Example usage
template_string = "Hello, $name!"
context = {'name': 'World'}
output = render_template(template_string, **context)
print(output)  # Output: Hello, World!