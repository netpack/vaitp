import memcache

# Initialize the memcache client
memcache_client = memcache.Client(['127.0.0.1:11211'], debug=0)

def create_new_token(user_id):
    # Logic to create a new token
    return f"token_for_{user_id}"

def get_user_token(user_id):
    token = memcache_client.get(user_id)
    if token is None:
        # Logic to create a new token
        token = create_new_token(user_id)
        memcache_client.set(user_id, token)
    return token