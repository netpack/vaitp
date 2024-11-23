from flask import Flask, request, jsonify
import logging

app = Flask(__name__)

# Disable debug mode in production
app.debug = False

@app.route('/some_endpoint', methods=['GET'])
def some_endpoint():
    try:
        # Your endpoint logic here
        return jsonify({"message": "Success"}), 200
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return jsonify({"error": "An internal error occurred."}), 500

if __name__ == '__main__':
    app.run()