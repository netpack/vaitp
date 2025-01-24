import smtplib
import ssl
import os
from getpass import getpass

def send_email(smtp_server, port, sender_email, receiver_email, message, use_tls=True):
    # Create a secure SSL context
    context = ssl.create_default_context()
    
    # Connect to the SMTP server with certificate verification
    with smtplib.SMTP(smtp_server, port) as server:
        if use_tls:
            server.starttls(context=context)  # Secure the connection with TLS
        password = getpass(f"Enter password for {sender_email}: ")
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, message)

# Example usage
try:
    send_email('smtp.example.com', 587, 'sender@example.com', 'receiver@example.com', 'Test message')
except smtplib.SMTPAuthenticationError:
    print("SMTP Authentication Error, check your email/password credentials")
except Exception as e:
    print(f"An error occurred: {e}")
