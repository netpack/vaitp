
from flask import Flask, request, redirect, url_for, session
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = 'your_secret_key'
csrf = CSRFProtect(app)

@app.route('/submit', methods=['POST'])
def submit():
    if not csrf.validate_csrf(request.form):  # Replace @csrf.exempt with this line
        return redirect(url_for('error'))
    # Process the form submission
    return redirect(url_for('success'))

@app.route('/success')
def success():
    return "Form submitted successfully!"

@app.route('/error')
def error():
    return "CSRF token is missing or invalid!"

if __name__ == '__main__':
    app.run()