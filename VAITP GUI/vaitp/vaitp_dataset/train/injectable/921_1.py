from flask import Flask, request, jsonify

app = Flask(__name__)

# A function to safely retrieve the client's IP address
def get_client_ip():
    # Get the real IP address from the request
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        # Split the list and take the first IP address
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.remote_addr
    
    # Validate the IP address (you can implement your own validation logic)
    if validate_ip(ip):
        return ip
    else:
        # Handle the case where the IP is not valid (e.g., log an error, raise an exception)
        return None

# Example IP validation function
def validate_ip(ip):
    # Implement your validation logic here
    # For example, you could check if the IP is from a known range or format
    return True  # Placeholder for actual validation logic

@app.route('/some_endpoint', methods=['GET'])
def some_endpoint():
    client_ip = get_client_ip()
    if client_ip:
        # Proceed with the request using the validated IP
        return jsonify({"client_ip": client_ip}), 200
    else:
        # Handle invalid IP scenario
        return jsonify({"error": "Invalid IP address"}), 400

if __name__ == '__main__':
    app.run()