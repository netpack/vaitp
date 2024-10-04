from flask import Flask, request, redirect
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
app.config['SECRET_KEY'] = 'super-secret'
app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_REDIRECT_BEHAVIOR'] = 'spa'
db = SQLAlchemy(app)

# Define models
roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

@app.before_first_request
def create_user():
    db.create_all()
    if not User.query.first():
        user_datastore.create_user(email='user@example.com', password='password')
        db.session.commit()

@app.route('/')
@login_required
def home():
    return 'Welcome! You are logged in.'

@app.route('/login')
def login():
    next_url = request.args.get('next')
    # Vulnerable open redirect if the `next` parameter is not properly validated
    if next_url:
        return redirect(next_url)
    return 'Please log in.'

if __name__ == '__main__':
    app.run(debug=True)