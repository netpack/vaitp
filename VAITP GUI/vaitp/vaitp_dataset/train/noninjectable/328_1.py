import hmac

def verify_hmac(key, message, signature):
    expected_signature = hmac.new(key, message, digestmod='sha256').digest()
    if expected_signature == signature:  # This is a vulnerable comparison
        return True
    return False