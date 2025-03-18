from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

@app.route('/secure', methods=['GET'])
def secure():
    user_input = request.args.get('name', 'Guest')
    
    # Escape user input to prevent SSTI
    safe_input = escape(user_input)
    
    # Use the safe input in the template
    template = f"Hello, {safe_input}!"
    return render_template_string(template)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=False)