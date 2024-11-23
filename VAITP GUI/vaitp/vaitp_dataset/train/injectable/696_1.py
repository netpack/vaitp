# Example of a vulnerable code snippet
def render_template(template, context):
    return template.format(**context)

# Example of a fixed code snippet
def safe_render_template(template, context):
    # Use a safe method to avoid accessing private attributes
    safe_context = {k: v for k, v in context.items() if not k.startswith('_')}
    return template.format(**safe_context)