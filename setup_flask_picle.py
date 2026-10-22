import os

DATASET_DIR = "vaitp_dataset"
VULN_FILE = f"{DATASET_DIR}/vulnerable/flask_pickle_1.py"
PATCH_FILE = f"{DATASET_DIR}/injectable/flask_pickle_1.py"

def setup_files():
    if not os.path.exists(f"{DATASET_DIR}/vulnerable"): os.makedirs(f"{DATASET_DIR}/vulnerable")
    if not os.path.exists(f"{DATASET_DIR}/injectable"): os.makedirs(f"{DATASET_DIR}/injectable")

    # 1. Vulnerable: Unpickles a cookie value
    with open(VULN_FILE, "w") as f:
        f.write("""
from flask import Flask, request, make_response
import pickle
import base64
import os

app = Flask(__name__)

@app.route('/')
def index():
    # VULNERABLE: Reads 'auth' cookie, b64 decodes, and unpickles
    # Common in legacy apps storing objects in cookies
    token = request.cookies.get('auth')
    
    if not token:
        resp = make_response("No auth token")
        resp.set_cookie('auth', 'guest_token_placeholder')
        return resp
        
    try:
        # 1. Decode Base64
        pickled_data = base64.b64decode(token)
        # 2. Unpickle (RCE Trigger)
        user_obj = pickle.loads(pickled_data)
        return f"Welcome back, user object: {user_obj}"
    except Exception as e:
        return f"Auth Error: {e}"

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
""")

    # 2. Patched: Uses JSON instead of Pickle
    with open(PATCH_FILE, "w") as f:
        f.write("""
from flask import Flask, request, make_response
import json
import base64
import os

app = Flask(__name__)

@app.route('/')
def index():
    # PATCH: Use JSON for serialization. It is safe from RCE.
    token = request.cookies.get('auth')
    
    if not token:
        resp = make_response("No auth token")
        # We assume new tokens are JSON
        resp.set_cookie('auth', base64.b64encode(b'{"user": "guest"}').decode())
        return resp
        
    try:
        json_data = base64.b64decode(token)
        # JSON loads cannot execute code
        user_obj = json.loads(json_data)
        return f"Welcome back, {user_obj}"
    except Exception as e:
        return f"Auth Error: {e}"

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
""")
    print("[INFO] Flask Pickle Cookie test files created.")

if __name__ == "__main__":
    setup_files()
