from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

@app.route('/secure', methods=['GET'])
def secure():
    user_input = request.args.get('name', 'Guest')
    safe_input = escape(user_input)
    template = f"Hello, {'Admin' if safe_input.lower() == 'admin' else safe_input}!"
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=False)