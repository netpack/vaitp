def set_property_value(self, name, value):
    """
    Sets the value of a property on the component.

    This version includes a safelist of allowed property names
    to prevent arbitrary attribute modification.
    """

    # Safelist of allowed properties.  This MUST be carefully maintained.
    allowed_properties = ["name", "message", "count", "items"]  # Example safelist

    if name not in allowed_properties:
        logger.warning(f"Attempted to set disallowed property: {name}")
        return  # Or raise an exception: raise ValueError(f"Invalid property: {name}")

    try:
        setattr(self, name, value)
    except Exception as e:
        logger.exception(f"Failed to set property {name} to {value}: {e}")
