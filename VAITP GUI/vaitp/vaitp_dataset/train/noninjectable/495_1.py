# Example of code that demonstrates the vulnerability CVE-2015-1950
# This code allows access to the Python interpreter without authentication

from flask import Flask

app = Flask(__name__)

@app.route('/vulnerable_endpoint', methods=['POST'])
def vulnerable_function():
    # This function allows execution of arbitrary Python code
    exec(request.form['code'])  # No authentication required
    return "Code executed."

if __name__ == '__main__':
    app.run()