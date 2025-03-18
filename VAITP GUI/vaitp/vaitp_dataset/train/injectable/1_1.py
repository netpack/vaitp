from flask import Flask, redirect, request

app = Flask("example")

@app.route("/redirecting")
def redirecting():
    url = request.args.get("url", "/")
    if not url.startswith("/"):
        return False
    return redirect(url)
