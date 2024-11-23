import asyncio
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP

class VulnerableSMTP(SMTP):
    async def handle_DATA(self, server, session, envelope):
        # No validation for sender addresses, allowing spoofing
        print(f"Received email from: {envelope.mail_from}")
        return '250 OK'

async def main():
    controller = Controller(VulnerableSMTP, port=1025)
    controller.start()
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())