from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/rhn/audit/scap/Search.do', methods=['GET', 'POST'])
def search():
    # Get user input
    user_input = request.form.get('query', '')

    # Vulnerable: directly rendering user input without escaping
    response = render_template_string('<h1>Search Results for: {}</h1>'.format(user_input))
    return response

if __name__ == '__main__':
    app.run()