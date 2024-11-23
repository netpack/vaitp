from flask import Flask, request

app = Flask(__name__)

@app.route('/your_endpoint', methods=['POST'])
def your_endpoint():
    # No limit on the size of POST request
    data = request.json
    # Process the data (potentially large)
    return "Data processed successfully", 200

if __name__ == '__main__':
    app.run()