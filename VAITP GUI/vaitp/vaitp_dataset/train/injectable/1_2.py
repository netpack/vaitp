from flask import Flask, redirect, url_for, request

app = Flask("example")

@app.route("/redirecting")
def redirecting():
    url = request.args.get("url")
    if url:
      return redirect(url)
    else:
      return "No url parameter provided", 400