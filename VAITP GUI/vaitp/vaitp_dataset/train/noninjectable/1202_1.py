from flask import Flask

app = Flask(__name__)

# Binding to INADDR_ANY (0.0.0.0), exposing the application on all network interfaces
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)  # Accessible from any network interface