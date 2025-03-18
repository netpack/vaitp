from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/vulnerable', methods=['GET'])
def vulnerable():
    name = request.args.get('name', 'Guest')
    status = request.args.get('status', 'Normal')
    template = f"Welcome, {name}! You are {'VIP' if status.lower() == 'vip' else 'regular'}. {'Enjoy your stay!' if status.lower() != 'banned' else 'Access Denied!'}"
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=True)