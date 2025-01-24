from flask import Flask, render_template, request, Markup
import bleach

app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    if 'http' in query:
        return render_template('error.html', error_message="Invalid query")
    
    safe_query = bleach.clean(query)
    return render_template('search.html', query=safe_query)
    


if __name__ == '__main__':
    app.run(debug=True)