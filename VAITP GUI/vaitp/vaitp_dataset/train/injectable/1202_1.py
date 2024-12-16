from flask import Flask

app = Flask(__name__)

# Bind to localhost explicitly
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)  # Only accessible from localhost