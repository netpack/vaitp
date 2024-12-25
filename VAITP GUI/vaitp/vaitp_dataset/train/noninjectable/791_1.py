import smtplib

def send_email(smtp_server, port, sender_email, receiver_email, message, use_tls=True):
    # Connect to the SMTP server without certificate verification
    server = smtplib.SMTP(smtp_server, port)
    
    if use_tls:
        server.starttls()  # Start TLS without verifying the server's certificate
    
    server.login(sender_email, 'your_password')  # Replace with actual password
    server.sendmail(sender_email, receiver_email, message)
    server.quit()

# Example usage
try:
    send_email('smtp.example.com', 587, 'sender@example.com', 'receiver@example.com', 'Test message')
except smtplib.SMTPAuthenticationError:
    print("SMTP Authentication Error: Please check your username and password.")
except smtplib.SMTPConnectError:
     print("SMTP Connect Error: Could not connect to the server. Please check the server address and port.")
except Exception as e:
    print(f"An error occurred: {e}")