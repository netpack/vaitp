from flask import Flask, request, jsonify
import uuid
import hashlib

app = Flask(__name__)

# In-memory store for user PINs (for demonstration purposes)
user_pins = {
    "user1": hashlib.sha256("secure_pin".encode()).hexdigest()  # Hashed PIN
}

# Function to verify the PIN
def verify_pin(username, pin):
    hashed_pin = hashlib.sha256(pin.encode()).hexdigest()
    return user_pins.get(username) == hashed_pin

@app.route('/api/change_wifi_settings', methods=['POST'])
def change_wifi_settings():
    username = request.json.get('username')
    pin = request.json.get('pin')
    
    if not verify_pin(username, pin):
        return jsonify({"error": "Unauthorized"}), 403

    # Proceed with changing Wi-Fi settings
    # ...

    return jsonify({"success": "Wi-Fi settings changed successfully"})

if __name__ == '__main__':
    app.run()