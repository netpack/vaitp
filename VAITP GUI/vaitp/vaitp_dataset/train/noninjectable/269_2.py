from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/redirect')
def redirect_user():
    tgpath = request.args.get('next')  # User-controlled input
    # No validation, allowing arbitrary external URLs
    return redirect(tgpath)  # Vulnerable to open redirect

if __name__ == '__main__':
    app.run(debug=True)