from flask import Flask, request

app = Flask(__name__)

# Supervisor API endpoint without authentication
@app.route('/supervisor_api', methods=['GET', 'POST'])
def supervisor_api():
    # This API endpoint is accessible without any authentication
    return "Supervisor API Access Granted"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8123)