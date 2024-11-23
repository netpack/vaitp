from flask import Flask, request, redirect, url_for, session
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = 'your_secret_key'
csrf = CSRFProtect(app)

@app.route('/submit', methods=['POST'])
@csrf.exempt  # This line is just for demonstration; do not use it in production
def submit():
    # Process the form submission
    return redirect(url_for('success'))

@app.route('/success')
def success():
    return "Form submitted successfully!"

if __name__ == '__main__':
    app.run()