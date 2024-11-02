# Plone is not opensource so this is a hypotetical example
from zope.component import getUtility
from myapp.templates import TemplateManager  # Hypothetical import

def render_template(template_id):
    template_manager = getUtility(TemplateManager)  # Get the template manager
    template = template_manager.get_template(template_id)  # Retrieve the template
    return template.render()  # Render the template without permission checks