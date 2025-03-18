
from flask import Flask, redirect, url_for, request
from urllib.parse import urlparse

app = Flask("example")

@app.route("/redirecting")
def redirecting():
    url = request.args.get("url")
    if not url:
        return "No URL provided"

    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        return "Invalid URL"

    if not (parsed_url.scheme.lower() in ['http', 'https'] and parsed_url.netloc.lower() not in ['localhost', '127.0.0.1']):
        return "Invalid URL"

    return redirect(url)


if __name__ == "__main__":
    app.run(debug=True)