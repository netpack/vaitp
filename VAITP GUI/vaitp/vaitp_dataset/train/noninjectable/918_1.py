# Example of vulnerable code that represents the CVE-2018-11776 vulnerability

from flask import Flask, request

app = Flask(__name__)

@app.route('/execute', methods=['POST'])
def execute_action():
    # Directly using user input without validation
    action = request.form.get('action')

    # Vulnerable to remote code execution if action is not properly namespaced
    if action:
        # Execute the action directly (this is where the vulnerability lies)
        exec(action)  # Dangerous! This allows arbitrary code execution

    return "Action executed"

if __name__ == '__main__':
    app.run()