from flask import Flask, request, escape, render_template_string

app = Flask(__name__)

@app.route('/rhn/audit/scap/Search.do', methods=['GET', 'POST'])
def search():
    # Get user input
    user_input = request.form.get('query', '')

    # Properly escape user input to prevent XSS
    safe_input = escape(user_input)

    # Render the response safely
    response = render_template_string('<h1>Search Results for: {{ query }}</h1>', query=safe_input)
    return response

if __name__ == '__main__':
    app.run()