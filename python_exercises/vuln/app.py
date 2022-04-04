from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    module = request.args.get("module")
    exec("import urllib%d as urllib" % int(module)) # Compliant module is safely cast to an integer

# cd /home/fred/msi/ano2/VAITP/python_exercises/vuln
# . vaitp_env/bin/activate
# export FLASK_APP=app
# mv vul08_correct_app.py app.py
# flask run
#
##exploit:
# curl http://127.0.0.1:5000/?module=\"; ls
