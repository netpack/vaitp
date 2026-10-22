import os

DATASET_DIR = "vaitp_dataset"
VULN_FILE = f"{DATASET_DIR}/vulnerable/flask_jwt_1.py"
PATCH_FILE = f"{DATASET_DIR}/injectable/flask_jwt_1.py"

def setup_files():
    if not os.path.exists(f"{DATASET_DIR}/vulnerable"): os.makedirs(f"{DATASET_DIR}/vulnerable")
    if not os.path.exists(f"{DATASET_DIR}/injectable"): os.makedirs(f"{DATASET_DIR}/injectable")

    # 1. Vulnerable: Manually checks 'alg' header and allows 'none'
    with open(VULN_FILE, "w") as f:
        f.write("""
from flask import Flask, request, jsonify
import jwt # PyJWT
import os

app = Flask(__name__)
SECRET = "my_secret_key"

@app.route('/admin/reset', methods=['POST'])
def admin_reset():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return "Missing Token", 401
    
    token = auth_header.split(" ")[1]
    
    try:
        # VULNERABLE: Developer manually checks header logic
        # If attacker sends alg='none', we skip signature verification
        unverified_header = jwt.get_unverified_header(token)
        
        if unverified_header.get('alg') == 'none':
            payload = jwt.decode(token, options={"verify_signature": False})
        else:
            payload = jwt.decode(token, SECRET, algorithms=["HS256"])
            
        if payload.get('role') == 'admin':
            # Side-effect to prove we reached admin
            os.system('touch /tmp/pwned_jwt')
            return "Admin Reset Successful"
        else:
            return "Forbidden", 403
            
    except Exception as e:
        return f"Error: {e}", 400

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
""")

    # 2. Patched: Strictly enforces algorithms
    with open(PATCH_FILE, "w") as f:
        f.write("""
from flask import Flask, request, jsonify
import jwt
import os

app = Flask(__name__)
SECRET = "my_secret_key"

@app.route('/admin/reset', methods=['POST'])
def admin_reset():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return "Missing Token", 401
    
    token = auth_header.split(" ")[1]
    
    try:
        # PATCH: Explicitly define allowed algorithms. 
        # PyJWT will reject 'none' automatically if not in the list.
        # We do NOT use verify_signature=False.
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
            
        if payload.get('role') == 'admin':
            os.system('touch /tmp/pwned_jwt')
            return "Admin Reset Successful"
        else:
            return "Forbidden", 403
            
    except Exception as e:
        return f"Error: {e}", 400

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
""")
    print("[INFO] Flask JWT None-Alg test files created.")

if __name__ == "__main__":
    setup_files()
