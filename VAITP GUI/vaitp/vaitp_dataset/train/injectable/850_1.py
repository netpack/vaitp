from flask import Flask, request, jsonify
import uuid
import hashlib
import hmac
import secrets

app = Flask(__name__)

# In-memory store for user PINs (for demonstration purposes)
user_pins = {
    "user1": hashlib.sha256(secrets.token_bytes(32) + "secure_pin".encode()).hexdigest()  # Hashed PIN with salt
}

# Function to verify the PIN
def verify_pin(username, pin):
    if username not in user_pins:
        return False
    
    stored_hash = user_pins.get(username)
    salt = bytes.fromhex(stored_hash[:64])
    hashed_pin = hashlib.sha256(salt + pin.encode()).hexdigest()
    return stored_hash == hashed_pin

@app.route('/api/change_wifi_settings', methods=['POST'])
def change_wifi_settings():
    username = request.json.get('username')
    pin = request.json.get('pin')
    
    if not username or not pin:
      return jsonify({"error": "Missing username or pin"}), 400
    
    if not verify_pin(username, pin):
        return jsonify({"error": "Unauthorized"}), 403

    # Proceed with changing Wi-Fi settings
    # ...

    return jsonify({"success": "Wi-Fi settings changed successfully"})

if __name__ == '__main__':
    app.run(debug=False)