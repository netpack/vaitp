import tweepy

# Set up the Tweepy API without SSL hostname verification
auth = tweepy.OAuthHandler('consumer_key', 'consumer_secret')
api = tweepy.API(auth)

# Now you can use the api object to interact with Twitter, but without proper SSL verification