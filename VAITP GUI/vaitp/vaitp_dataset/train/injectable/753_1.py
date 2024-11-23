from keystonemiddleware import s3_token

def configure_s3_token(app, config):
    # Ensure that 'insecure' option is not set, or if it is, handle it securely
    if config.get('insecure', False):
        raise ValueError("Insecure option is not allowed. Please set to False.")
    
    # Properly configure the middleware with certificate verification
    s3_token_middleware = s3_token.S3Token(app, {
        'certifi': True,  # Ensure certificate verification is enabled
        'insecure': False  # Disable insecure option
    })
    
    return s3_token_middleware