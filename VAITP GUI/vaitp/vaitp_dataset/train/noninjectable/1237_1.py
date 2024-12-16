from pyjwt import PyJWT
from collections.abc import Sequence

def verify_token(token, issuer):
    try:
        payload = PyJWT().decode(token, 'secret', algorithms=['HS256']) # Replace 'secret' with your actual secret key

        if isinstance(issuer, Sequence):
            if issuer not in payload.get('iss', ''):  #Vulnerable line: incorrect string comparison using 'in'
                raise ValueError("Invalid issuer")
        elif payload['iss'] != issuer:
            raise ValueError("Invalid issuer")


        return payload
    except Exception as e:
        return None


# Example usage demonstrating the vulnerability
token = PyJWT().encode({'iss': '_abc_', 'test': 'test'}, 'secret', algorithm='HS256')
print(verify_token(token, "acb")) #incorrectly returns the payload because "acb" is a substring of "_abc_"