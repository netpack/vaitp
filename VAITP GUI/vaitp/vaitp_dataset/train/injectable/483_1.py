from pymemcache.client import base

# Create a Memcached client
client = base.Client(('localhost', 11211))

def get_data_from_memcache(key):
    # Fetch data from memcache with proper validation
    data = client.get(key)
    
    if not is_valid_data(data):
        raise ValueError("Invalid data received from memcache")
    
    return data

def is_valid_data(data):
    # Implement validation logic to check the authenticity of the data
    # This is a placeholder for actual validation logic.
    # For example, you might check a signature or a checksum.
    if data is None:
        return False  # No data means invalid
    return True  # Replace with actual validation logic

# Example usage
key = 'example_key'
try:
    data = get_data_from_memcache(key)
    print(data)
except ValueError as e:
    print(e)