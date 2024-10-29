import hmac

def constant_time_compare(val1, val2):
    if len(val1) != len(val2):
        return False
    return hmac.compare_digest(val1, val2)  # This is a constant-time comparison

def verify_hmac(key, message, signature):
    expected_signature = hmac.new(key, message, digestmod='sha256').digest()
    return constant_time_compare(expected_signature, signature)