from flask import Flask, request

app = Flask(__name__)

@app.route('/submit', methods=['POST'])
def submit():
    # Get the raw data from the request
    raw_data = request.data

    # Check for null byte (0x00) in the raw data
    if b'\x00' in raw_data:
        return "Invalid input: Null byte detected", 400

    # Process the form data safely
    form_data = request.form.to_dict()
    # Further processing of form_data...

    return "Data processed successfully", 200

if __name__ == '__main__':
    app.run()