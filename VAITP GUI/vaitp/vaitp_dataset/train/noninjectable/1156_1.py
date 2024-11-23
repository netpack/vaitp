from nicegui import ui

# Vulnerable route that allows local file inclusion
@ui.route('/_nicegui/{__version__}/resources/{key}/{path:path}')
def serve_resource(key, path):
    # Directly serving the requested resource without validation
    return ui.send_file(f'resources/{key}/{path}')

ui.run()