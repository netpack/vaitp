# Example of a secure mod_python publisher implementation that prevents indirect access to dangerous modules

from mod_python import apache

# A whitelist of allowed modules
ALLOWED_MODULES = {'safe_module': None} # Store modules as keys for efficient lookup

def handler(req):
    # Get the module name from the request
    module_name = req.args.get('module', '')

    # Check if the requested module is in the allowed list
    if module_name not in ALLOWED_MODULES:
        req.write("Access denied to module: {}".format(module_name))
        return apache.HTTP_FORBIDDEN

    try:
        # Import and use the safe module
        mod = __import__(module_name)
        result = mod.safe_function()  # Call a safe function from the allowed module
        req.write(str(result)) # Ensure result is a string for writing
        return apache.OK
    except Exception as e:
         req.write("Error accessing module: {}".format(e))
         return apache.HTTP_INTERNAL_SERVER_ERROR