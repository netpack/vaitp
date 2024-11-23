import cgi
import subprocess

def handle_request(environ):
    # Parse the query string safely
    query_string = environ.get('QUERY_STRING', '')
    safe_query = cgi.escape(query_string)  # Escape special characters to prevent command injection

    # Example of using the safe input in a command
    # This is a safe way to handle commands by not allowing direct execution of user input
    command = ['echo', safe_query]  # Use a list to avoid shell injection
    result = subprocess.run(command, capture_output=True, text=True)

    return result.stdout