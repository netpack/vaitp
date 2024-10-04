from flask import Flask, request

app = Flask(__name__)

@app.route('/echo', methods=['GET'])
def echo():
    user_input = request.args.get('input')
    # Vulnerability: Directly returning user input without validation or encoding
    return f"User input was: {user_input}"

if __name__ == "__main__":
    app.run()