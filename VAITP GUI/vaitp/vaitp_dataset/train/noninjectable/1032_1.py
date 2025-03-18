from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/vulnerable', methods=['GET'])
def vulnerable():
    user_input = request.args.get('name', 'Guest')
    
    # Directly using user input in a Jinja2 template (SSTI Vulnerability)
    template = f"Hello, {user_input}!"
    return render_template_string(template)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
