from flask import Flask, request, redirect, url_for

app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.route('/submit', methods=['POST'])
def submit():
    # Process the form submission without CSRF protection
    return redirect(url_for('success'))

@app.route('/success')
def success():
    return "Form submitted successfully!"

if __name__ == '__main__':
    app.run()