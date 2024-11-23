from flask import Flask, request, escape

app = Flask(__name__)

@app.route('/example', methods=['GET'])
def example():
    # Properly escape the user input to prevent XSS
    api_param = escape(request.args.get('api', ''))
    return f'API parameter: {api_param}'

if __name__ == '__main__':
    app.run()