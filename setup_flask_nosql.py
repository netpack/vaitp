import os

DATASET_DIR = "vaitp_dataset"
VULN_FILE = f"{DATASET_DIR}/vulnerable/flask_nosql_1.py"
PATCH_FILE = f"{DATASET_DIR}/injectable/flask_nosql_1.py"

def setup_files():
    if not os.path.exists(f"{DATASET_DIR}/vulnerable"): os.makedirs(f"{DATASET_DIR}/vulnerable")
    if not os.path.exists(f"{DATASET_DIR}/injectable"): os.makedirs(f"{DATASET_DIR}/injectable")

    # Shared MockDB logic to simulate MongoDB behavior
    MOCK_DB_CODE = """
class MockDB:
    def __init__(self):
        # The hidden admin user
        self.users = [{"u": "admin", "p": "s3cr3t_P@ssw0rd_99"}]

    def find_one(self, query):
        for user in self.users:
            match = True
            for key, val in query.items():
                # Simulate MongoDB Query Logic
                user_val = user.get(key)
                
                # 1. Direct Match
                if user_val == val:
                    continue
                
                # 2. Operator Match (e.g., $ne)
                if isinstance(val, dict):
                    if "$ne" in val and user_val != val["$ne"]:
                        continue
                        
                match = False
                break
            if match:
                return user
        return None

db = MockDB()
"""

    # 1. Vulnerable: Passes parsed JSON directly to the DB
    with open(VULN_FILE, "w") as f:
        f.write(f"""
from flask import Flask, request, jsonify
import os

app = Flask(__name__)

{MOCK_DB_CODE}

@app.route('/login', methods=['POST'])
def login():
    if not request.is_json: return "JSON required", 400
    data = request.get_json()
    
    # VULNERABLE: The app expects strings, but Flask parses 
    # nested JSON objects (dicts) if the attacker sends them.
    # We pass 'data' directly to the DB query logic.
    user = db.find_one(data)
    
    if user and user['u'] == 'admin':
        # Side-effect to prove Admin Access
        os.system('touch /tmp/pwned_nosql')
        return jsonify({{"status": "logged_in", "user": "admin"}})
    
    return jsonify({{"error": "invalid"}}), 401

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
""")

    # 2. Patched: Type checking input
    with open(PATCH_FILE, "w") as f:
        f.write(f"""
from flask import Flask, request, jsonify
import os

app = Flask(__name__)

{MOCK_DB_CODE}

@app.route('/login', methods=['POST'])
def login():
    if not request.is_json: return "JSON required", 400
    data = request.get_json()
    
    username = data.get('u')
    password = data.get('p')

    # PATCH: Explicit Type Checking
    # We ensure password is a STRING, preventing dictionary operators like $ne
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({{"error": "Invalid input types"}}), 400

    # Safe query construction
    user = db.find_one({{"u": username, "p": password}})
    
    if user and user['u'] == 'admin':
        os.system('touch /tmp/pwned_nosql')
        return jsonify({{"status": "logged_in", "user": "admin"}})
    
    return jsonify({{"error": "invalid"}}), 401

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
""")
    print("[INFO] Flask NoSQL Injection test files created.")

if __name__ == "__main__":
    setup_files()
