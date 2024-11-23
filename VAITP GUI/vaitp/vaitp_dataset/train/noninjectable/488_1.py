from flask import Flask, redirect, request

app = Flask(__name__)

def _validate_redirect_url(target):
    # Vulnerable validation of the redirect URL
    return True  # This allows all URLs, including malicious ones

@app.route('/redirect')
def unsafe_redirect():
    target = request.args.get('url')
    if _validate_redirect_url(target):
        return redirect(target)  # Vulnerable to arbitrary redirects
    return 'Invalid URL', 400

if __name__ == '__main__':
    app.run()