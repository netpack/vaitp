# Example of restricting Zope Page Template editing to trusted users only

from AccessControl import ClassSecurityInfo
from Products.CMFCore.permissions import ManagePortal
from Products.CMFCore.utils import getToolByName

class SecurePageTemplate:
    security = ClassSecurityInfo()

    # Restrict the permission to manage page templates
    security.declareProtected(ManagePortal, 'editPageTemplate')
    def editPageTemplate(self, template_id, content):
        # Logic to edit the page template
        pass

# Usage in a Zope application to ensure only trusted users can edit
def restrict_access(context):
    acl_users = getToolByName(context, 'acl_users')
    # Remove untrusted users from the Manager role
    for user in acl_users.getUsers():
        if 'untrusted_role' in user.getRoles():
            user.removeRole('Manager')