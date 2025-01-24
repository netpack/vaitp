from flask import Flask
import os

app = Flask(__name__)

# Bind to localhost explicitly
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='127.0.0.1', port=port, debug=False)