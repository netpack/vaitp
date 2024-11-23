from flask import Flask, request, jsonify

app = Flask(__name__)

# In-memory store for user PINs (for demonstration purposes)
user_pins = {
    "user1": "secure_pin"  # Plaintext PIN
}

@app.route('/api/change_wifi_settings', methods=['POST'])
def change_wifi_settings():
    username = request.json.get('username')
    pin = request.json.get('pin')
    
    # Vulnerable: No verification or rate limiting for PIN
    if user_pins.get(username) == pin:
        # Proceed with changing Wi-Fi settings
        # ...
        return jsonify({"success": "Wi-Fi settings changed successfully"})
    
    return jsonify({"error": "Unauthorized"}), 403

if __name__ == '__main__':
    app.run()