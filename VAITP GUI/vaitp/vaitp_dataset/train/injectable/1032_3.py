from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

@app.route('/secure', methods=['GET'])
def secure():
    items = request.args.get('items', '').split(',')
    escaped_items = [escape(item) for item in items]
    template = f"Items: {'<br>'.join([f'{item.capitalize()}!' if item.lower() == 'special' else item for item in escaped_items])}"
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=False)