# Vulnerable route in Flask-AppBuilder before the fix
@app.route('/users', methods=['GET'])
@admin_required
def get_users():
    password_filter = request.args.get('password')
    # This allows querying users based on partial hashed password strings
    users = User.query.filter(User.password_hash.like(f'%{password_filter}%')).all()
    return jsonify([user.username for user in users])