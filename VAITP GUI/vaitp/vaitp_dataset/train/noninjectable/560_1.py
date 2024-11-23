def create_object(context, type_name, id, **kwargs):
    # Directly using createObject without permission checks
    obj = context.portal_skins.custom.createObject(type_name, id, **kwargs)
    return obj