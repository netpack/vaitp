from flask import Flask, render_template, request, escape

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # Check if query contains 'http'
    if 'http' not in query:
        # Escape the query to prevent XSS
        error_message = escape(query)
        return render_template('error.html', error_message=error_message)
    
    # Proceed with normal search logic
    # ...

if __name__ == '__main__':
    app.run(debug=True)