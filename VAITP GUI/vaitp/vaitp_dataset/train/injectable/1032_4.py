from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

@app.route('/secure', methods=['GET'])
def secure():
    name = escape(request.args.get('name', 'Guest'))
    status = escape(request.args.get('status', 'Normal'))
    template = f"Welcome, {name}! You are {'VIP' if status.lower() == 'vip' else 'regular'}. {'Enjoy your stay!' if status.lower() != 'banned' else 'Access Denied!'}"
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=False)