import email
from email.message import EmailMessage

# Create an email message
msg = EmailMessage()
msg['Subject'] = 'Test Email'
msg['From'] = 'sender@example.com'
msg['To'] = 'recipient@example.com'

# Improperly set a header with a newline, demonstrating the vulnerability
msg['X-Custom-Header'] = 'Value with newline\nInjected Header: value'  # Vulnerable to injection

# Serialize the email message
serialized_msg = msg.as_string()

print(serialized_msg)