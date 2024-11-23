from flask import Flask, redirect, request

app = Flask(__name__)

def make_safe_url(url):
    # Vulnerable URL validation that allows multiple slashes
    return url  # No validation, allows arbitrary URLs

@app.route('/redirect')
def unsafe_redirect():
    target_url = request.args.get('url')
    unsafe_url = make_safe_url(target_url)
    return redirect(unsafe_url)

if __name__ == '__main__':
    app.run()