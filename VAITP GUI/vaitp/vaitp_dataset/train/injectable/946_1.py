from flask import Flask, redirect, request, url_for, abort
from werkzeug.exceptions import BadRequest

app = Flask(__name__)

# Allowed hosts for redirection
ALLOWED_HOSTS = {'example.com', 'localhost'}

def is_safe_url(target):
    # Check if the target URL is safe
    from urllib.parse import urlparse
    parsed_url = urlparse(target)
    return parsed_url.netloc in ALLOWED_HOSTS

@app.route('/login')
def login():
    next_url = request.args.get('next')
    if next_url and not is_safe_url(next_url):
        raise BadRequest("Unsafe redirect URL")
    return redirect(next_url or url_for('home'))

@app.route('/register')
def register():
    next_url = request.args.get('next')
    if next_url and not is_safe_url(next_url):
        raise BadRequest("Unsafe redirect URL")
    return redirect(next_url or url_for('home'))

@app.route('/home')
def home():
    return "Welcome to the home page!"

if __name__ == '__main__':
    app.run()