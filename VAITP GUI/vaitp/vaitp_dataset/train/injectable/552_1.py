from flask import Flask, redirect, request, abort
import re

app = Flask(__name__)

def make_safe_url(url):
    # Validate the URL to prevent redirects to arbitrary locations
    # This regex allows only specific schemes (http, https) and disallows multiple slashes
    if re.match(r'^(http|https)://[^/\\]+(/[^\\]*)?$', url):
        return url
    else:
        abort(400)  # Bad Request if the URL is invalid

@app.route('/redirect')
def safe_redirect():
    target_url = request.args.get('url')
    safe_url = make_safe_url(target_url)
    return redirect(safe_url)

if __name__ == '__main__':
    app.run()