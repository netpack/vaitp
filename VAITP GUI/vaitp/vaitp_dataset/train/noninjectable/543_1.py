from jinja2 import Environment, FileSystemLoader

# Create a Jinja2 environment without autoescaping
env = Environment(
    loader=FileSystemLoader('templates')
)

def render_template(template_name, context):
    # Render the template with the provided context
    template = env.get_template(template_name)
    return template.render(context)

# Example usage
if __name__ == "__main__":
    user_input = input("Enter template name: ")
    user_context = {
        'user_input': user_input  # Directly using user input in context
    }
    output = render_template(user_input, user_context)
    print(output)