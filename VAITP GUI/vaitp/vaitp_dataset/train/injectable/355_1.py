
import memcache
import uuid
import time

# Initialize the memcache client
memcache_client = memcache.Client(['127.0.0.1:11211'], debug=0)

TOKEN_PREFIX = "token_"
TOKEN_EXPIRY = 3600  # Token expiry time in seconds

def create_new_token(user_id):
    token = f"{TOKEN_PREFIX}{uuid.uuid4()}"
    return token

def is_token_valid(token):
    return token.startswith(TOKEN_PREFIX) and len(token) > len(TOKEN_PREFIX)

def get_user_token(user_id):
    cache_key = f"user_token:{user_id}"
    cached_data = memcache_client.get(cache_key)

    if cached_data:
        token, timestamp = cached_data.split(":", 1)
        if is_token_valid(token) and int(timestamp) > time.time():
            return token

    token = create_new_token(user_id)
    expiry_time = int(time.time() + TOKEN_EXPIRY)
    memcache_client.set(cache_key, f"{token}:{expiry_time}", time=TOKEN_EXPIRY)

    return token