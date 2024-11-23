import email
from email.message import EmailMessage

# Create an email message
msg = EmailMessage()
msg['Subject'] = 'Test Email'
msg['From'] = 'sender@example.com'
msg['To'] = 'recipient@example.com'

# Properly quote a newline in the header to prevent injection
msg['X-Custom-Header'] = 'Value with newline\n'  # Vulnerable to injection

# Serialize the email message
serialized_msg = msg.as_string()

print(serialized_msg)