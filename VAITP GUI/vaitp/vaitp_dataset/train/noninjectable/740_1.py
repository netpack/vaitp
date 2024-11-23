from jinja2 import Environment, FileSystemLoader

# Set up Jinja2 environment without autoescaping
env = Environment(
    loader=FileSystemLoader('templates')
)

# Example of a vulnerable rendering function
def vulnerable_render(template_name, context):
    template = env.get_template(template_name)
    return template.render(context)

# Example of an exposed resource.db() method
class Resource:
    def db(self):
        # This method could be exploited if accessed via Jinja2
        return "Database access"

# Usage example
if __name__ == "__main__":
    resource = Resource()
    user_context = {
        'resource': resource,  # Exposing the resource object directly
        'unsafe_variable': '{{ resource.db() }}'  # Potentially dangerous template code
    }
    output = vulnerable_render('example_template.html', user_context)
    print(output)