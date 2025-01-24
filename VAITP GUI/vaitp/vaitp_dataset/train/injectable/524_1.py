from flask import Flask, request, redirect, url_for, session
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = 'your_secret_key'
csrf = CSRFProtect(app)

@app.route('/perform_action', methods=['POST'])
def perform_action():
    # Perform sensitive action
    return redirect(url_for('success'))

@app.route('/success')
def success():
    return "Action performed successfully!"

if __name__ == '__main__':
    app.run()