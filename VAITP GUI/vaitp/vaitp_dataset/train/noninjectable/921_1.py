from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/some_endpoint', methods=['GET'])
def some_endpoint():
    # Directly using the X-Forwarded-For header without validation
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    # Log the client IP (which can be spoofed)
    print(f"Client IP: {client_ip}")
    
    # Proceed with the request using the potentially spoofed IP
    return jsonify({"client_ip": client_ip}), 200

if __name__ == '__main__':
    app.run()