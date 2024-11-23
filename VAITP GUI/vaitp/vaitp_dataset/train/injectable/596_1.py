from flask import Flask, request, abort

app = Flask(__name__)

# Mock user database
users = {
    'admin': {'role': 'administrator'},
    'editor': {'role': 'editor'},
    'developer': {'role': 'developer'}
}

def is_admin(user):
    return users.get(user, {}).get('role') == 'administrator'

@app.route('/admin/user/add', methods=['POST'])
def add_user():
    current_user = request.form.get('current_user')
    new_username = request.form.get('new_username')
    new_role = request.form.get('new_role')

    # Check if the current user is an administrator
    if not is_admin(current_user):
        abort(403)  # Forbidden

    # Proceed to add the new user
    users[new_username] = {'role': new_role}
    return f'User  {new_username} added with role {new_role}.', 201

if __name__ == '__main__':
    app.run()