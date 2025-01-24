# Fixed version of the route to prevent querying by hashed password
@app.route('/users', methods=['GET'])
@admin_required
def get_users_fixed():
    # Do not allow filtering by password hash
    users = User.query.all()
    return jsonify([user.username for user in users])