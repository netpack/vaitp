# Import the novajoin plugin
from novajoin import Novajoin

# Create a Novajoin object with the keystone URL and credentials
novajoin = Novajoin("https://keystone.example.com/v3", "admin", "password")

# Generate a FreeIPA token for any user
token = novajoin.generate_token("user")

# Print the token
print(token)