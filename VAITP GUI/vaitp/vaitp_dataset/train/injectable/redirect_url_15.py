@app.route('/')
def hello():
    return redirect(url_for('hello'))