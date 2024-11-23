from nicegui import ui

# Define a safe route for serving resources
@ui.route('/safe_resources/<path:key>/<path:path>')
def safe_resources(key, path):
    # Implement logic to validate 'key' and 'path' to prevent directory traversal
    if is_valid_key(key) and is_valid_path(path):
        # Safely serve the requested resource
        return serve_resource(key, path)
    else:
        return ui.response('Forbidden', status=403)

def is_valid_key(key):
    # Implement key validation logic
    return key in allowed_keys

def is_valid_path(path):
    # Implement path validation logic to prevent directory traversal
    return not any(part in path for part in ['..', '/'])

def serve_resource(key, path):
    # Logic to serve the resource safely
    return ui.send_file(f'resources/{key}/{path}')

ui.run()