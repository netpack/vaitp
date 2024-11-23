import smtplib

class VulnerableSMTP(smtplib.SMTP):
    def starttls(self, keyfile=None, certfile=None):
        # Attempt to start TLS without checking the response
        self.docmd("STARTTLS")
        # No error handling for failed StartTLS

if __name__ == "__main__":
    smtp = VulnerableSMTP('smtp.example.com', 587)
    smtp.ehlo()
    smtp.starttls()  # No error raised if StartTLS fails
    smtp.ehlo()
    print("TLS established (potentially vulnerable).")