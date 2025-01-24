import email
from email.message import EmailMessage
from email.header import Header

# Create an email message
msg = EmailMessage()
msg['Subject'] = 'Test Email'
msg['From'] = 'sender@example.com'
msg['To'] = 'recipient@example.com'

# Properly encode the header to prevent injection
msg['X-Custom-Header'] = Header('Value with newline\n', 'utf-8').encode()

# Serialize the email message
serialized_msg = msg.as_string()

print(serialized_msg)
