from flask import Flask, redirect, request

app = Flask(__name__)

@app.route('/login')
def login():
    next_url = request.args.get('next')
    return redirect(next_url or '/home')

@app.route('/register')
def register():
    next_url = request.args.get('next')
    return redirect(next_url or '/home')

@app.route('/home')
def home():
    return "Welcome to the home page!"

if __name__ == '__main__':
    app.run()