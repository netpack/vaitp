from jinja2 import Environment, FileSystemLoader, select_autoescape

# Create a Jinja2 environment with autoescaping enabled
env = Environment(
    loader=FileSystemLoader('templates'),
    autoescape=select_autoescape(['html', 'xml'])  # Only allow specific file types
)

def render_template(template_name, context):
    # Render the template with the provided context safely
    template = env.get_template(template_name)
    return template.render(context)

# Example usage
if __name__ == "__main__":
    safe_context = {
        'key': 'value'  # Only include safe variables
    }
    output = render_template('safe_template.html', safe_context)
    print(output)