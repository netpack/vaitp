import smtplib
import ssl

def send_email(smtp_server, port, sender_email, receiver_email, message, use_tls=True):
    # Create a secure SSL context
    context = ssl.create_default_context()
    
    # Connect to the SMTP server with certificate verification
    with smtplib.SMTP(smtp_server, port) as server:
        if use_tls:
            server.starttls(context=context)  # Secure the connection with TLS
        server.login(sender_email, 'your_password')  # Replace with actual password
        server.sendmail(sender_email, receiver_email, message)

# Example usage
# The password should be handled more securely, not hardcoded, and it's required for the code to actually send an email.
# This example is left as is to show how to fix the error for now, but should be updated in real world scenario
try:
    send_email('smtp.example.com', 587, 'sender@example.com', 'receiver@example.com', 'Test message')
except smtplib.SMTPAuthenticationError:
    print("SMTP Authentication Error, check your email/password credentials")
except Exception as e:
    print(f"An error occurred: {e}")
