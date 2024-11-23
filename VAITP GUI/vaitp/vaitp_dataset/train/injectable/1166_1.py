from flask import Flask, request, escape

app = Flask(__name__)

@app.route('/post', methods=['POST'])
def handle_post():
    content_type = request.headers.get('Content-Type', '')
    # Properly escape the Content-Type header to prevent XSS
    safe_content_type = escape(content_type)
    return f"Content-Type received: {safe_content_type}"

if __name__ == '__main__':
    app.run()