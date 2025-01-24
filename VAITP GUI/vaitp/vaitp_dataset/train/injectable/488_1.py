from flask import Flask, redirect, request, abort
from urllib.parse import urlparse

app = Flask(__name__)

def _validate_redirect_url(target):
    if not target:
        return False
    try:
        parsed_url = urlparse(target)
        if not parsed_url.scheme or not parsed_url.netloc:
            return False
        if parsed_url.scheme not in ['http', 'https']:
            return False
        return True
    except:
        return False

@app.route('/redirect')
def safe_redirect():
    target = request.args.get('url')
    if _validate_redirect_url(target):
        return redirect(target)
    else:
        abort(400)

if __name__ == '__main__':
    app.run()