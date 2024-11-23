from flask import Flask, request

app = Flask(__name__)

@app.route('/update-resource-data/', methods=['POST'])
def update_resource_data():
    filename = request.form.get('filename')
    data = request.form.get('data')

    # Vulnerable code allowing directory traversal
    with open(filename, 'w') as f:
        f.write(data)

    return 'File updated successfully', 200

if __name__ == '__main__':
    app.run()