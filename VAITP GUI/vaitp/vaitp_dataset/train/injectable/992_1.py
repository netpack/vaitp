from mod_python import apache

def handler(req):
    # Restrict access to certain objects
    restricted_objects = ['/admin', '/config']

    # Get the requested URL
    requested_url = req.uri

    # Check if the requested URL is in the list of restricted objects
    if requested_url in restricted_objects:
        req.write("Access Denied")
        return apache.HTTP_FORBIDDEN

    # Proceed with handling the request for non-restricted objects
    req.write("Access Granted")
    return apache.OK