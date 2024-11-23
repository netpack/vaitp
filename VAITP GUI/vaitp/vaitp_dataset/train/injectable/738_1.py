import tweepy
import ssl
import certifi

# Create an SSL context that verifies the hostname
ssl_context = ssl.create_default_context()
ssl_context.load_verify_locations(cafile=certifi.where())

# Set up the Tweepy API with the SSL context
auth = tweepy.OAuthHandler('consumer_key', 'consumer_secret')
api = tweepy.API(auth, ssl_context=ssl_context)

# Now you can use the api object to interact with Twitter securely