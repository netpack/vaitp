@app.route('/your_endpoint')
def your_view_function():
    # Assume `data` is fetched from a database and contains user input
    data = get_data_from_database()

    # Directly rendering user input without escaping, leading to XSS vulnerability
    return render_template('your_template.html', endpoint=data['endpoint'])