# Example of vulnerable code for CVE-2019-10904 in a hypothetical roundup.cgi or wsgi_handler.py

from flask import Flask, request

app = Flask(__name__)

@app.route('/<path:path>', methods=['GET'])
def handle_request(path):
    # Simulating a resource lookup
    resource = lookup_resource(path)
    
    if resource is None:
        # Directly returning the user input in the error message can lead to XSS
        return f"Error: Resource '{path}' not found", 404

    return resource

def lookup_resource(path):
    # Simulated resource lookup logic
    # Return None if resource is not found
    return None

if __name__ == '__main__':
    app.run()