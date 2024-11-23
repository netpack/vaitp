from oic import oic
from oic.oauth2 import Client
from oic.utils.keyio import KeyJar

class VulnerableConsumer(oic.consumer.Consumer):
    def parse_authz(self, authz_response):
        # No automatic checking of IdToken signature algorithm
        id_token = authz_response['id_token']

        # Allow 'none' algorithm
        if id_token['alg'] == 'none':
            print("Warning: IdToken signature algorithm is 'none'")

        # Return unverified IdToken
        return id_token

# Example usage
client = Client(client_id='your_client_id', client_secret='your_client_secret')
consumer = VulnerableConsumer(client)
authz_response = {
    'id_token': {
        'alg': 'none',  # Vulnerable to accepting 'none' algorithm
        'iat': 1609459200  # Example iat claim
    }
}
id_token = consumer.parse_authz(authz_response)
print("Parsed IdToken:", id_token)