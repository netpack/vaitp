from flask import Flask
from flask_caching import Cache
import pickle

app = Flask(__name__)

# Using Pickle for serialization, which is vulnerable
cache = Cache(app, config={'CACHE_TYPE': 'simple', 'CACHE_DEFAULT_TIMEOUT': 300})

@app.route('/set_cache/<key>/<value>')
def set_cache(key, value):
    # Store data in cache using Pickle serialization
    cache.set(key, pickle.dumps(value))

@app.route('/get_cache/<key>')
def get_cache(key):
    # Retrieve data from cache and deserialize it
    value = cache.get(key)
    if value is not None:
        return pickle.loads(value)
    return 'Cache not found', 404

if __name__ == '__main__':
    app.run(debug=True)