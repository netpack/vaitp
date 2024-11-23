from bottle import Bottle, request, response

app = Bottle()

@app.route('/example')
def example():
    # Get parameters from request
    param1 = request.query.get('param1')
    param2 = request.query.get('param2')

    # Validate parameters to prevent caching issues
    if param1 is None or param2 is None:
        response.status = 400
        return "Missing parameters"

    # Process request safely
    return f"Param1: {param1}, Param2: {param2}"

if __name__ == '__main__':
    app.run(host='localhost', port=8080)