# Plone is not opensource so this is a hypotetical example
from plone import api
from zope.component import getUtility
from myapp.templates import TemplateManager  # Hypothetical import

def render_template(template_id, user):
    template_manager = getUtility(TemplateManager)  # Get the template manager
    template = template_manager.get_template(template_id)  # Retrieve the template
    
    # Check if the user has permission to render the template
    if api.user.has_permission('Modify portal content', user):
        return template.render()  # Render the template if permission is granted
    else:
        raise PermissionError("You do not have permission to render this template.")