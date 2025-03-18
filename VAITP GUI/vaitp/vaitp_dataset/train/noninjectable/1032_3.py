from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/vulnerable', methods=['GET'])
def vulnerable():
    items = request.args.get('items', '').split(',')
    template = f"Items: {'<br>'.join([f'{item.capitalize()}!' if item.lower() == 'special' else item for item in items])}"
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=True)