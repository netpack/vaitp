from flask import Flask, request, redirect, url_for

app = Flask(__name__)

@app.route('/perform_action', methods=['POST'])
def perform_action():
    # Perform sensitive action without CSRF protection
    return redirect(url_for('success'))

@app.route('/success')
def success():
    return "Action performed successfully!"

if __name__ == '__main__':
    app.run()