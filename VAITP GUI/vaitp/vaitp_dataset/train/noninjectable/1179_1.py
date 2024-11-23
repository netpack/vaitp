# Example of vulnerable code that allows arbitrary code execution

from flask import Flask, request

app = Flask(__name__)

@app.route('/execute', methods=['POST'])
def execute():
    # Dangerous execution of user input
    user_input = request.form['code']
    
    # Directly executing user input as code (vulnerable)
    exec(user_input)
    
    return "Code executed."

if __name__ == '__main__':
    app.run()