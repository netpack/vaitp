from flask import Flask, request, redirect

app = Flask(__name__)

def is_safe_url(url):
    # Ensure the URL starts with a '/' to restrict to internal paths
    return url.startswith('/')

@app.route('/redirect')
def redirect_user():
    tgpath = request.args.get('next')  # User-controlled input
    if not is_safe_url(tgpath):
        tgpath = '/'  # Redirect to a safe default (root)
    return redirect(tgpath)

if __name__ == '__main__':
    app.run(debug=True)