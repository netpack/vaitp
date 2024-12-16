from oic import oic
from oic.oauth2 import Client
from oic.utils.keyio import KeyJar
from oic.utils.authn import ClientSecretBasic
from oic.utils.time_util import utc_now

class SecureConsumer(oic.consumer.Consumer):
    def parse_authz(self, authz_response):
        # Ensure the IdToken signature algorithm is checked
        if 'alg' not in authz_response['id_token']:
            raise ValueError("Missing 'alg' in IdToken")
        
        expected_alg = 'RS256'  # Example expected algorithm
        if authz_response['id_token']['alg'] != expected_alg:
            raise ValueError(f"Unexpected IdToken signature algorithm: {authz_response['id_token']['alg']}")

        # Reject 'none' algorithm
        if authz_response['id_token']['alg'] == 'none':
            raise ValueError("IdToken signature algorithm 'none' is not allowed")

        # Verify the IdToken
        id_token = authz_response['id_token']
        if not self.verify_id_token(id_token):
            raise ValueError("IdToken verification failed")

        # Check iat claim for sanity
        if 'iat' in id_token:
            if id_token['iat'] > utc_now():
                raise ValueError("iat claim is in the future")

        return id_token

    def verify_id_token(self, id_token):
        # Implement actual verification logic here
        print('vaitp example')