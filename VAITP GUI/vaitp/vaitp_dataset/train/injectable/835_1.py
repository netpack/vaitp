import html

def send_notification_email(user_email, message):
    # Sanitize the message to prevent HTML injection
    safe_message = html.escape(message)
    
    email_body = f"""
    <html>
        <body>
            <p>You have a new message:</p>
            <p>{safe_message}</p>
        </body>
    </html>
    """
    
    # Code to send the email (omitted for brevity)
    # send_email(user_email, email_body)