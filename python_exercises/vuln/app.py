import pickle
import base64
from flask import Flask, request
from shlex import quote

app = Flask(__name__)


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

    
@app.route("/vuln", methods=["POST"])
def vuln():
    print(f"Got request: {request.form['pickled']}")
    data = base64.urlsafe_b64decode(request.form['pickled'])
    print()
    print("-----")
    print()
    print(data)

    #if re.match(r"^system$",data):
        #print("vuln")

    depickled = pickle.loads(quote(data))#fixed
    print(f"Data was unpickled: {depickled}")

    return '', 204


# Usage:
# cd /home/fred/msi/ano2/VAITP/python_exercises/vuln
# . vaitp_env/bin/activate
# export FLASK_APP=app
# flask run
