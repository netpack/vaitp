# Example of a vulnerable route in Flask-AppBuilder before the fix
@app.route('/users', methods=['GET'])
@admin_required
def get_users():
    password_filter = request.args.get('password')
    users = User.query.filter(User.password_hash.like(f'%{password_filter}%')).all()
    return jsonify([user.username for user in users])

# Fixed version of the route to prevent querying by hashed password
@app.route('/users', methods=['GET'])
@admin_required
def get_users_fixed():
    # Do not allow filtering by password hash
    users = User.query.all()
    return jsonify([user.username for user in users])