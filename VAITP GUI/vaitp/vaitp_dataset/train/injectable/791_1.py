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
send_email('smtp.example.com', 587, 'sender@example.com', 'receiver@example.com', 'Test message')