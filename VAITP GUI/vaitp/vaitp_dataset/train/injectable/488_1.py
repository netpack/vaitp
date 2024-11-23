from flask import Flask, redirect, request, abort
import re

app = Flask(__name__)

def _validate_redirect_url(target):
    # Basic validation of the redirect URL
    if not target:
        return False
    # Ensure the target URL is a safe URL
    if re.match(r'^https?://', target):
        return True
    return False

@app.route('/redirect')
def safe_redirect():
    target = request.args.get('url')
    if _validate_redirect_url(target):
        return redirect(target)
    else:
        abort(400)  # Bad request if the URL is invalid

if __name__ == '__main__':
    app.run()