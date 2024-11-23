from flask import Flask, request

app = Flask(__name__)

@app.route('/submit', methods=['POST'])
def submit():
    # Directly process form data without checking for null bytes
    form_data = request.form.to_dict()
    
    # Simulating potential processing of the data
    # This could lead to unexpected behavior if null bytes are present
    print("Received data:", form_data)

    return "Data processed successfully", 200

if __name__ == '__main__':
    app.run()