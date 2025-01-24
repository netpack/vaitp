from flask import Flask, request, abort
from functools import wraps
import secrets
import os

app = Flask(__name__)

# Example of a simple OAuth token validation function
VALID_OAUTH_TOKENS = set()
if "VALID_OAUTH_TOKENS" in os.environ:
    tokens = os.environ["VALID_OAUTH_TOKENS"].split(",")
    for token in tokens:
      VALID_OAUTH_TOKENS.add(token.strip())
else:
  VALID_OAUTH_TOKENS.add(secrets.token_urlsafe(32))
  print(f"Warning: VALID_OAUTH_TOKENS environment variable not set, using default token: {VALID_OAUTH_TOKENS}")

def validate_oauth_token(token):
    # Replace with actual token validation logic
    return token in VALID_OAUTH_TOKENS

def require_oauth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            abort(401)  # Unauthorized
        try:
            auth_type, token = auth_header.split(" ", 1)
            if auth_type.lower() != "bearer":
                abort(401)
        except ValueError:
            abort(401)
        
        if not validate_oauth_token(token):
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/celery/tasks', methods=['GET'])
@require_oauth
def list_tasks():
    # Logic to list Celery tasks
    return {"tasks": ["task1", "task2"]}

@app.route('/api/celery/execute', methods=['POST'])
@require_oauth
def execute_task():
    # Logic to execute a Celery task
    return {"status": "task executed"}

if __name__ == '__main__':
    app.run(debug=False)
