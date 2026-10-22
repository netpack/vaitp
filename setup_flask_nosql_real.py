import os

DATASET_DIR = "vaitp_dataset"
VULN_FILE = f"{DATASET_DIR}/vulnerable/flask_nosql_real.py"
PATCH_FILE = f"{DATASET_DIR}/injectable/flask_nosql_real.py"

def setup_files():
    if not os.path.exists(f"{DATASET_DIR}/vulnerable"): os.makedirs(f"{DATASET_DIR}/vulnerable")
    if not os.path.exists(f"{DATASET_DIR}/injectable"): os.makedirs(f"{DATASET_DIR}/injectable")

    # Shared DB Initialization Code
    DB_INIT = """
import time
from pymongo import MongoClient

def get_db():
    # Retry logic because Mongo takes a few seconds to start
    for _ in range(5):
        try:
            client = MongoClient('mongodb://mongodb:27017/', serverSelectionTimeoutMS=2000)
            client.server_info() # Trigger connection
            return client.testdb
        except:
            time.sleep(1)
    return None

def seed_db():
    db = get_db()
    if db is not None:
        db.users.drop()
        db.users.insert_one({"u": "admin", "p": "s3cr3t_P@ssw0rd_99"})
        print("DB Seeded")
"""

    # 1. Vulnerable Code
    with open(VULN_FILE, "w") as f:
        f.write(f"""
from flask import Flask, request, jsonify
import os
{DB_INIT}

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    if not request.is_json: return "JSON required", 400
    data = request.get_json()
    
    db = get_db()
    if db is None: return "DB Error", 500

    # VULNERABLE: Passing raw dictionary to find_one
    # Allows {{ "$ne": "" }} injection
    user = db.users.find_one(data)
    
    if user and user['u'] == 'admin':
        os.system('touch /tmp/pwned_mongo_real')
        return jsonify({{"status": "logged_in", "user": "admin"}})
    
    return jsonify({{"error": "invalid"}}), 401

if __name__ == "__main__":
    seed_db()
    app.run(host='0.0.0.0', port=5000)
""")

    # 2. Patched Code
    with open(PATCH_FILE, "w") as f:
        f.write(f"""
from flask import Flask, request, jsonify
import os
{DB_INIT}

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    if not request.is_json: return "JSON required", 400
    data = request.get_json()
    
    username = data.get('u')
    password = data.get('p')

    # PATCH: Explicit Type Checking
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({{"error": "Invalid input types"}}), 400

    db = get_db()
    # Safe query construction
    user = db.users.find_one({{"u": username, "p": password}})
    
    if user and user['u'] == 'admin':
        os.system('touch /tmp/pwned_mongo_real')
        return jsonify({{"status": "logged_in", "user": "admin"}})
    
    return jsonify({{"error": "invalid"}}), 401

if __name__ == "__main__":
    seed_db()
    app.run(host='0.0.0.0', port=5000)
""")
    print("[INFO] Real MongoDB NoSQL test files created.")

if __name__ == "__main__":
    setup_files()
