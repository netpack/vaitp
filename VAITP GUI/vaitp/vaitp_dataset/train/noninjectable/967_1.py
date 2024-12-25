```
```python
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/data', methods=['POST'])
def handle_data():
    # Vulnerable code that executes arbitrary code from user input
    user_input = request.json.get('data', '')
    
    # Dangerous: executing user input directly
    # Instead of exec(user_input), do something safe
    print(f"Received data: {user_input}") #Example of logging the input

    return jsonify({"message": "Data processed"}), 200

if __name__ == '__main__':
    app.run(debug=True)