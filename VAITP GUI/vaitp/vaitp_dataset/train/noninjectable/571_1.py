from flask import Flask, render_template, escape

app = Flask(__name__)

def get_data_from_database():
    # Placeholder function to simulate fetching data from a database
    # In a real app, you'd connect to your database here.
    return {'endpoint': '<script>alert("XSS Vulnerability")</script>'}

@app.route('/your_endpoint')
def your_view_function():
    # Assume `data` is fetched from a database and contains user input
    data = get_data_from_database()

    # Escaping user input before rendering to prevent XSS vulnerability
    return render_template('your_template.html', endpoint=escape(data['endpoint']))

if __name__ == '__main__':
    app.run(debug=True)