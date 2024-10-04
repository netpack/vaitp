from flask import Flask, request, redirect, url_for
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required
from flask_sqlalchemy import SQLAlchemy
from urllib.parse import urlparse, urljoin

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
app.config['SECRET_KEY'] = 'super-secret'
app.config['SECURITY_REGISTERABLE'] = True
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

def is_safe_url(target):
    """
    Check if the target URL is safe for redirects.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

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
    # Securely validate the `next` parameter before redirecting
    if next_url and is_safe_url(next_url):
        return redirect(next_url)
    return 'Please log in.'

if __name__ == '__main__':
    app.run(debug=True)