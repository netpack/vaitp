from flask import Flask, request, abort

app = Flask(__name__)

# Set a maximum content length to prevent large POST requests
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024  # 16 KB

@app.route('/your_endpoint', methods=['POST'])
def your_endpoint():
    # Handle the POST request
    data = request.json
    # Process the data
    return "Data processed successfully", 200

@app.errorhandler(413)
def request_entity_too_large(error):
    return "Request entity too large", 413

if __name__ == '__main__':
    app.run()