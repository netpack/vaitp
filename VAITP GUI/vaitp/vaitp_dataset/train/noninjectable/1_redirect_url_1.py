from flask import Flask, redirect

app = Flask("example")

@app.route("/redirecting")
def redirecting():
    url = request.args["url"]
    return redirect(url)