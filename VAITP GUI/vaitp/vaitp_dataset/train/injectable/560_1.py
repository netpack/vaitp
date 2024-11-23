from Products.CMFCore.utils import getToolByName
from Products.CMFCore.exceptions import Unauthorized

def safe_create_object(context, type_name, id, **kwargs):
    # Ensure that the user has permission to create the object
    if not context.checkPermission('Add portal content', context):
        raise Unauthorized("You do not have permission to create this object.")
    
    # Create the object safely
    portal_types = getToolByName(context, 'portal_types')
    if type_name in portal_types.listTypeInfo():
        new_object = portal_types.constructContent(type_name, context, id, **kwargs)
        return new_object
    else:
        raise ValueError("Invalid type name provided.")