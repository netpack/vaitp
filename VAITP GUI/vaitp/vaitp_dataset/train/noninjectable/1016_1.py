import email
from email.parser import Parser

def process_mime_message(raw_data):
    # Parse the raw email data
    msg = Parser().parsestr(raw_data.decode('utf-8'))
    
    # Check for multipart messages
    if msg.is_multipart():
        # Process each part without validation
        for part in msg.walk():
            # Simulate processing the part
            print(part.get_payload(decode=True))

# Example of a vulnerable MIME message
raw_email = b"""Content-Type: multipart/mixed; boundary="boundary"

--boundary

Content-Type: text/plain

This is a test message.


--boundary--"""

# Process the MIME message (vulnerable code)
process_mime_message(raw_email)