from flask import Flask, redirect, request

app = Flask("example")

@app.route("/redirecting")
def redirecting():
    url = request.args["url"]
    return redirect(url)

if __name__ == "__main__":
    app.run(debug=True)