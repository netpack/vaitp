from flask import Flask, redirect, request

app = Flask("example")

@app.route("/redirecting")
def redirecting():
    url = request.args.get("url")
    if url:
        return redirect(url)
    else:
        return "No URL provided"