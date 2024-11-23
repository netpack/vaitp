# Example of how to prevent arbitrary code execution in a web application context

from flask import Flask, request, escape

app = Flask(__name__)

@app.route('/execute', methods=['POST'])
def execute():
    # Simulated safe execution environment
    user_input = request.form['code']
    
    # Escape user input to prevent code injection
    safe_input = escape(user_input)

    # Log the safe input instead of executing it
    print(f"Received safe input: {safe_input}")
    
    return "Code executed safely."

if __name__ == '__main__':
    app.run()