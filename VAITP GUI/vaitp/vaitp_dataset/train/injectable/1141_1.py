from flask import Flask, session

app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.route('/')
def index():
    session['data'] = 'example_data'
    # Set session cookie with Secure and HttpOnly flags
    response = app.make_response("Session cookie set")
    response.set_cookie('session', session.sid, secure=True, httponly=True)
    return response

if __name__ == '__main__':
    app.run()