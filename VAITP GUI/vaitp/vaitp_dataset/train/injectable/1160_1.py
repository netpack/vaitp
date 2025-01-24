import os
from flask import Flask, request, abort, session
from secrets import token_hex

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a strong secret key


def execute_expression(project_id, expression):
    if not isinstance(project_id, str) or not project_id.isalnum():
      abort(400)  # Bad request for invalid project_id
    if not isinstance(expression, str) or len(expression) > 1024:
      abort(400)  # Bad request for invalid or too long expression
    
    # Placeholder for secure expression execution
    # DO NOT USE EVAL OR EXEC
    return f"Preview of {expression} for project {project_id}"

def generate_csrf_token():
    return token_hex(16)

@app.route('/preview-expression', methods=['POST'])
def preview_expression():
    csrf_token = session.get('csrf_token')
    if not csrf_token or csrf_token != request.form.get('csrf_token'):
        abort(403)
    
    project_id = request.form.get('project_id')
    expression = request.form.get('expression')
    
    return execute_expression(project_id, expression)

@app.before_request
def before_request():
    if 'csrf_token' not in session:
        session['csrf_token'] = generate_csrf_token()

if __name__ == '__main__':
    app.run(debug=False)
