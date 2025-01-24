import jinja2
from jinja2 import Environment, FileSystemLoader, select_autoescape

def render_template(template_string, context, template_path=None, trim_blocks=False, lstrip_blocks=False, extensions=None):
    if template_path:
        env = Environment(
            loader=FileSystemLoader(template_path),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=trim_blocks,
            lstrip_blocks=lstrip_blocks,
            extensions=extensions or []
        )
        template = env.from_string(template_string)
    else:
        env = Environment(
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=trim_blocks,
            lstrip_blocks=lstrip_blocks,
            extensions=extensions or []
        )
        template = env.from_string(template_string)
        
    return template.render(context)