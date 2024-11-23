# Example of restricting access to Zope Page Templates to trusted users only

from AccessControl import getSecurityManager
from AccessControl import ClassSecurityInfo
from Products.Five import BrowserView

class SecurePageTemplate(BrowserView):
    security = ClassSecurityInfo()

    @security.protected('Manage Zope')
    def edit_template(self, template_id, new_content):
        # Ensure that only users with the Manager role can edit templates
        if not getSecurityManager().checkPermission('Manage Zope', self.context):
            raise Unauthorized("You do not have permission to edit this template.")
        
        # Proceed with editing the template
        template = self.context.restrictedTraverse(template_id)
        template.pt_edit(new_content)

# Usage
# This would be part of the Zope application where you define the view for editing templates.