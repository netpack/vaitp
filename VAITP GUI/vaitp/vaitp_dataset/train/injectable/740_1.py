from jinja2 import Environment, FileSystemLoader, select_autoescape

# Set up Jinja2 environment with autoescaping enabled
env = Environment(
    loader=FileSystemLoader('templates'),
    autoescape=select_autoescape(['html', 'xml'])  # Enable autoescaping for specific file types
)

# Example of a safe rendering function
def safe_render(template_name, context):
    template = env.get_template(template_name)
    return template.render(context)

# Usage example
if __name__ == "__main__":
    user_context = {
        'safe_variable': 'This is safe',
        # Avoid exposing any dangerous methods or attributes
    }
    output = safe_render('example_template.html', user_context)
    print(output)