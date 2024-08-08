import email.parser

# Use the recommended parser classes
parser = email.parser.BytesParser()
parsed_email = parser.parsebytes(b"From: example@example.com\nTo: test@test.com\nSubject: Test\n\nThis is a test email.")
print(parsed_email)
