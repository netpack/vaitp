import re

def sanitize_template(template):
    # Restrict the template to only allow safe placeholders
    allowed_pattern = re.compile(r'^[\w\s{}]+$')
    if not allowed_pattern.match(template):
        raise ValueError("Invalid template: contains unsafe characters.")
    return template

def configure_data_pipeline(template):
    # Sanitize the template to prevent remote code execution
    sanitized_template = sanitize_template(template)
    # Proceed with the configuration using the sanitized template
    # ... (rest of the pipeline configuration logic)

# Example usage
try:
    user_input_template = "{{ user_input }}"
    configure_data_pipeline(user_input_template)
except ValueError as e:
    print(e)