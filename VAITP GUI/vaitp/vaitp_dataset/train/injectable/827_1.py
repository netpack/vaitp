from flask import Flask
from flask_caching import Cache
import json

app = Flask(__name__)

# Use JSON for serialization instead of Pickle
cache = Cache(app, config={'CACHE_TYPE': 'simple', 'CACHE_DEFAULT_TIMEOUT': 300})

@app.route('/set_cache/<key>/<value>')
def set_cache(key, value):
    # Store data in cache using JSON serialization
    cache.set(key, json.dumps(value))

@app.route('/get_cache/<key>')
def get_cache(key):
    # Retrieve data from cache and deserialize it
    value = cache.get(key)
    if value is not None:
        return json.loads(value)
    return 'Cache not found', 404

if __name__ == '__main__':
    app.run(debug=True)