from flask import Flask, redirect

app = Flask("vaitp")

@app.route("/router")
def redirecting():
    dst = request.args["dsturl"]
    return redirect(url_for(dst))
