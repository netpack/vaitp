import os

DATASET_DIR = "vaitp_dataset"
VULN_FILE = f"{DATASET_DIR}/vulnerable/flask_ssrf_1.py"
PATCH_FILE = f"{DATASET_DIR}/injectable/flask_ssrf_1.py"

def setup_files():
    if not os.path.exists(f"{DATASET_DIR}/vulnerable"): os.makedirs(f"{DATASET_DIR}/vulnerable")
    if not os.path.exists(f"{DATASET_DIR}/injectable"): os.makedirs(f"{DATASET_DIR}/injectable")

    # 1. Vulnerable: Fetches any URL provided by user
    with open(VULN_FILE, "w") as f:
        f.write("""
from flask import Flask, request
import urllib.request
import os

app = Flask(__name__)

# --- INTERNAL ADMIN ENDPOINT (Hidden) ---
@app.route('/admin/run_maintenance')
def admin_job():
    # Only allow local requests (simulating internal network restriction)
    if request.remote_addr != '127.0.0.1':
        return "Forbidden: Internal use only", 403
        
    # The "Side Effect" we want to trigger
    os.system('touch /tmp/pwned_ssrf')
    return "Maintenance Complete"

# --- PUBLIC ENDPOINT (Vulnerable) ---
@app.route('/proxy')
def proxy_service():
    target = request.args.get('url')
    if not target: return "Missing URL"
    
    try:
        # VULNERABLE: No filtering on target URL.
        # Attacker can pass 'http://127.0.0.1:5000/admin/run_maintenance'
        # causing the server to attack itself.
        with urllib.request.urlopen(target) as response:
            return f"Fetched {len(response.read())} bytes"
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
""")

    # 2. Patched: Deny-list for local/private IPs
    with open(PATCH_FILE, "w") as f:
        f.write("""
from flask import Flask, request
import urllib.request
import os
from urllib.parse import urlparse
import socket

app = Flask(__name__)

@app.route('/admin/run_maintenance')
def admin_job():
    if request.remote_addr != '127.0.0.1':
        return "Forbidden: Internal use only", 403
    os.system('touch /tmp/pwned_ssrf')
    return "Maintenance Complete"

@app.route('/proxy')
def proxy_service():
    target = request.args.get('url')
    if not target: return "Missing URL"
    
    try:
        # PATCH: Resolve hostname and check for local IPs
        parsed = urlparse(target)
        hostname = parsed.hostname
        ip = socket.gethostbyname(hostname)
        
        # Simple check for localhost (in reality, you need a full private IP blocklist)
        if ip in ['127.0.0.1', '0.0.0.0', '::1']:
            return "Security Alert: Access to internal resources denied."

        with urllib.request.urlopen(target) as response:
            return f"Fetched {len(response.read())} bytes"
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
""")
    print("[INFO] Flask SSRF test files created.")

if __name__ == "__main__":
    setup_files()
