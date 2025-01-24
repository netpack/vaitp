
from flask import Flask, request, redirect, url_for
from werkzeug.utils import redirect

app = Flask(__name__)

@app.route('/redirect')
def redirect_user():
    tgpath = request.args.get('next')
    if not tgpath or not is_safe_url(tgpath):
        tgpath = url_for('index')
    return redirect(tgpath)

if __name__ == '__main__':
    app.run(debug=True)