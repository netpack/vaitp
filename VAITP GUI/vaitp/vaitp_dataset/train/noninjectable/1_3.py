import re
from flask import Flask, request, redirect

app = Flask(__name__)

# Naïve regexes:
ALLOWED_SCHEME_REGEX = re.compile(r"^https?://", re.IGNORECASE)
# This regex is intended to block any URL containing "localhost" or "127.0.0.1"
FORBIDDEN_HOST_REGEX = re.compile(r"(localhost|127\.0\.0\.1)", re.IGNORECASE) 
# This would NOT work: http://local%68ost.netpack.pt
# but this will: http://127.0.0.1:5000/redirect?url=http://local%2568ost.netpack.pt


@app.route("/redirect")
def redirect_view():
    url = request.args.get("url")
    if not url:
        return "No URL provided", 400

    # Check that the URL starts with http:// or https://
    if not ALLOWED_SCHEME_REGEX.match(url):
        return "Invalid URL", 400

    # Naïve check for forbidden hosts
    if FORBIDDEN_HOST_REGEX.search(url):
        return "Invalid URL", 400

    return redirect(url)

if __name__ == '__main__':
    app.run()
