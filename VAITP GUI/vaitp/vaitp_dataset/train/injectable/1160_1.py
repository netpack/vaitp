from flask import Flask, request, abort, session

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Ensure this is a strong secret key

@app.route('/preview-expression', methods=['POST'])
def preview_expression():
    # Check for CSRF token in the session
    csrf_token = session.get('csrf_token')
    if not csrf_token or csrf_token != request.form.get('csrf_token'):
        abort(403)  # Forbidden if CSRF token is invalid

    project_id = request.form.get('project_id')
    expression = request.form.get('expression')

    # Validate project_id and expression here
    # Execute the expression safely
    return execute_expression(project_id, expression)

def generate_csrf_token():
    # Function to generate a CSRF token
    pass

@app.before_request
def before_request():
    # Generate a CSRF token for the session if it doesn't exist
    if 'csrf_token' not in session:
        session['csrf_token'] = generate_csrf_token()

if __name__ == '__main__':
    app.run()