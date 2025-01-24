import jinja2

def render_template_safe(template_content, template_name, context):
  """Renders a Jinja2 template with a safe environment.
  
  This function uses a sandboxed environment to prevent execution of
  arbitrary Python code, even if template names are controlled by
  the user.

  Args:
    template_content: The string content of the template.
    template_name: The name of the template (used for caching).
    context: A dictionary of values to pass to the template.

  Returns:
    The rendered template string.

  Raises:
      jinja2.exceptions.TemplateError: If there is an issue with template
        compilation or rendering.
  """
  env = jinja2.Environment(
      loader=jinja2.DictLoader({template_name: template_content}),
      autoescape=True,
      enable_async=True,
      
      # Enable Sandbox
      extensions=['jinja2.ext.sandbox'],
      
      # Limit allowed expressions
      undefined=jinja2.Undefined,
  )
  
  
  try:
    template = env.get_template(template_name)
    return template.render(context)
  except jinja2.exceptions.TemplateError as e:
     raise

if __name__ == '__main__':
  # Example usage that demonstrates protection.
  
  # This template is potentially dangerous, if not using a safe setup.
  user_supplied_template = """
  Hello {{ user }}!
  {% if True %}
    {{ ''.__class__.__mro__[2].__subclasses__()[407]('evil_command', shell=True, stdout=-1).communicate()[0].strip() }}
  {% endif %}
  """

  try:
      rendered_template = render_template_safe(
          user_supplied_template,
          "user_template.html",
          {"user": "TestUser"}
      )
      print("Rendered template:", rendered_template)
  except jinja2.exceptions.TemplateError as e:
      print("Error while rendering template:", e)