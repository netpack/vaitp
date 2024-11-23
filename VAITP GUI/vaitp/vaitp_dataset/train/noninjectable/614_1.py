from flask import Flask, request

app = Flask(__name__)

# Debug mode enabled, which can expose the interactive debugger
app.debug = True

@app.route('/some_endpoint', methods=['GET'])
def some_endpoint():
    # Example code that may raise an exception
    raise Exception("An intentional error for demonstration.")

if __name__ == '__main__':
    app.run()