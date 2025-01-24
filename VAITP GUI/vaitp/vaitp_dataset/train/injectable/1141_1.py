from flask import Flask, session, make_response
from os import urandom

app = Flask(__name__)
app.secret_key = urandom(24)

@app.route('/')
def index():
    session['data'] = 'example_data'
    response = make_response("Session cookie set")
    response.set_cookie('session', session.sid, secure=True, httponly=True, samesite='Lax')
    return response

if __name__ == '__main__':
    app.run(ssl_context='adhoc')