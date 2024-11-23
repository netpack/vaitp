import cgi
import subprocess

def handle_request(environ, start_response):
    # Parse the query parameters safely
    form = cgi.FieldStorage(environ=environ)
    command = form.getvalue('command')

    # Validate the command to prevent arbitrary command execution
    allowed_commands = ['list', 'status', 'info']
    if command not in allowed_commands:
        start_response('400 Bad Request', [('Content-Type', 'text/plain')])
        return [b'Invalid command.']

    # Safely execute the command
    try:
        result = subprocess.run(['my_script', command], capture_output=True, text=True, check=True)
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return [result.stdout.encode()]
    except subprocess.CalledProcessError as e:
        start_response('500 Internal Server Error', [('Content-Type', 'text/plain')])
        return [f'Error executing command: {e}'.encode()]