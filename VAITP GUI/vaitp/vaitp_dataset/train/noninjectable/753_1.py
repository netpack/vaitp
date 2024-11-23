from keystonemiddleware import s3_token

def configure_s3_token(app, config):
    # Insecure option allows disabling certificate verification
    s3_token_middleware = s3_token.S3Token(app, {
        'insecure': config.get('insecure', False)  # Accepts insecure option
    })
    
    return s3_token_middleware