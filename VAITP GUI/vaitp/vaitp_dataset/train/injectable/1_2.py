from flask import Flask, redirect, url_for

app = Flask("example")

@app.route("/redirecting")
def redirecting():
    url = request.args["url"]
    return redirect(url_for(url)))