from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # Check if query contains 'http'
    if 'http' not in query:
        # Vulnerable to XSS as the user input is rendered without escaping
        error_message = query  # Directly using user input
        return render_template('error.html', error_message=error_message)
    
    # Proceed with normal search logic
    # ...

if __name__ == '__main__':
    app.run(debug=True)