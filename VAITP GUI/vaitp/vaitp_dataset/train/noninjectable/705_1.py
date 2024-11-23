from flask import Flask
from flask_caching import Cache

app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache'})

class Website:
    def __init__(self):
        self.user_vars = {}

    @property
    def user_vars(self):
        # Vulnerable code: directly exposing user variables without any checks
        return cache.get('user_vars', {})

    def set_user_var(self, key, value):
        user_vars = cache.get('user_vars', {})
        user_vars[key] = value
        cache.set('user_vars', user_vars)

    def get_user_var(self, key):
        user_vars = cache.get('user_vars', {})
        return user_vars.get(key)

# Example of usage
website = Website()
website.set_user_var('username', 'user1')
website.set_user_var('sensitive_info', 'secret')
print(website.user_vars)  # Output: {'username': 'user1', 'sensitive_info': 'secret'}