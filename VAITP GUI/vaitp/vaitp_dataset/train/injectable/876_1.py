from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, auth_required
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Configuration for Flask-Security
app.config['SECURITY_TOKEN_MAX_AGE'] = 0  # Disable token usage
app.config['SECRET_KEY'] = 'super-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Define User and Role models
class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(length=80), unique=True)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    email = db.Column(db.String(length=255), unique=True)
    password = db.Column(db.String(length=255))
    active = db.Column(db.Boolean(), default=True)
    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'message': 'Email and password required'}), 400
    
    email = data['email']
    password = data['password']
    
    user = user_datastore.find_user(email=email)
    if user and user.check_password(password):
         return jsonify({"message": "Login successful"}),200
    return jsonify({"message": "Invalid email or password"}),401

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'message': 'Email and password required'}), 400
    email = data['email']
    password = data['password']
    if user_datastore.find_user(email=email):
        return jsonify({'message': 'Email already registered'}), 409
    
    user = user_datastore.create_user(email=email, password=password)
    db.session.commit()
    user.set_password(password)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/change', methods=['POST'])
@auth_required('token')
def change():
    data = request.get_json()
    if not data or 'password' not in data:
         return jsonify({'message': 'Password required'}), 400
    new_password = data['password']
    user = security.current_user
    user.set_password(new_password)
    db.session.commit()
    return jsonify({"message": "Password Changed"}),200


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
