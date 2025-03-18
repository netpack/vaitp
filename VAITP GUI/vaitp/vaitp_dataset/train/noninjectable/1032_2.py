from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/vulnerable', methods=['GET'])
def vulnerable():
    user_input = request.args.get('name', 'Guest')
    template = f"Hello, {'Admin' if user_input.lower() == 'admin' else user_input}!"
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=True)