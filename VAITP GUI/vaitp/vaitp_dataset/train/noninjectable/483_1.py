from pymemcache.client import base

# Create a Memcached client
client = base.Client(('localhost', 11211))

def get_data_from_memcache(key):
    # Fetch data from memcache without proper validation
    data = client.get(key)
    return data

# Example usage
key = 'example_key'
data = get_data_from_memcache(key)
print(data)