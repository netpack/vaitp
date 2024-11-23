from werkzeug.serving import run_simple
from werkzeug.wrappers import Request, Response

def application(environ, start_response):
    request = Request(environ)
    # Your application logic here
    response = Response("Hello, World!", status=200)
    return response(environ, start_response)

if __name__ == "__main__":
    # Set debug=False to prevent debug shell access
    run_simple('0.0.0.0', 5000, application, use_reloader=False, use_debugger=False)