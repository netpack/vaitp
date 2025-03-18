import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64


def serialize_ocsp_response(response_data):
    """
    Serializes the OCSP response data using JSON instead of pickle.
    """
    return json.dumps(response_data).encode('utf-8')


def deserialize_ocsp_response(serialized_data):
    """
    Deserializes the OCSP response data using JSON instead of pickle.
    """
    try:
      return json.loads(serialized_data.decode('utf-8'))
    except json.JSONDecodeError:
        return None  # or raise a custom exception


if __name__ == '__main__':
  # Example usage:
    
    #Generating mock OCSP response Data
    key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    )
    public_key = key.public_key()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    ocsp_response = {
        'status': 'good',
        'certificate_serial': '1234567890',
        'responder_public_key': public_pem.decode('utf-8')
    }
    
    # Serialize the OCSP response
    serialized_response = serialize_ocsp_response(ocsp_response)
    print(f"Serialized Response (JSON): {serialized_response}")

    # Deserialize the OCSP response
    deserialized_response = deserialize_ocsp_response(serialized_response)
    print(f"Deserialized Response: {deserialized_response}")
    
    
    #Example of a corrupted serialized response that does not produce a correct deserialized output.
    corrupted_response = b'This is not JSON'
    
    corrupted_deserialized_response = deserialize_ocsp_response(corrupted_response)
    print(f"Deserialized Corrupted Response: {corrupted_deserialized_response}")