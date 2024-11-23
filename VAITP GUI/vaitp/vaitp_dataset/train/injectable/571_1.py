from flask import escape, render_template

@app.route('/your_endpoint')
def your_view_function():
    # Assume `data` is fetched from a database and contains user input
    data = get_data_from_database()

    # Properly escape the user input to prevent XSS
    safe_data = escape(data['endpoint'])

    return render_template('your_template.html', endpoint=safe_data)