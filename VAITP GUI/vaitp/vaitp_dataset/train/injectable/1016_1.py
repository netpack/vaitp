import email
from email import policy
from email.parser import BytesParser

def is_valid_mime_message(raw_data):
    # Parse the raw email data
    msg = BytesParser(policy=policy.default).parsebytes(raw_data)
    
    # Check for multipart messages
    if msg.is_multipart():
        # Iterate through the parts
        for part in msg.iter_parts():
            # Check for blank lines in the part
            if part.get_content_type() == 'text/plain':
                content = part.get_payload()
                if '\n\n' in content:
                    raise ValueError("Invalid MIME message: Contains two blank lines.")
    
    return True

# Example usage
try:
    raw_email = b"""Content-Type: multipart/mixed; boundary="boundary"
    
    --boundary
    Content-Type: text/plain
    
    This is a test message.
    
    --boundary--"""
    
    is_valid_mime_message(raw_email)
    print("Valid MIME message.")
except ValueError as e:
    print(e)