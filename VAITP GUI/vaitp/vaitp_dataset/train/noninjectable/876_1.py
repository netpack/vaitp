from flask import Flask, request, jsonify
from flask_security import Security, SQLAlchemyUser Datastore, UserMixin, RoleMixin

app = Flask(__name__)

# Configuration for Flask-Security
app.config['SECRET_KEY'] = 'super-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

# Define User and Role models
class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(length=80), unique=True)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    email = db.Column(db.String(length=255), unique=True)
    password = db.Column(db.String(length=255))

# Setup Flask-Security
user_datastore = SQLAlchemyUser Datastore(db, User, Role)
security = Security(app, user_datastore)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Handle login logic
        return jsonify({"token": "user_authentication_token"})  # Vulnerable: token returned on GET
    return jsonify({"message": "Login page"})

@app.route('/change', methods=['GET', 'POST'])
def change():
    if request.method == 'POST':
        # Handle change logic
        return jsonify({"token": "user_authentication_token"})  # Vulnerable: token returned on GET