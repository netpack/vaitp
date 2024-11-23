import asyncio
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP

class CustomSMTP(SMTP):
    async def handle_DATA(self, server, session, envelope):
        # Implement strict validation for sender addresses
        if not self.is_valid_sender(envelope.mail_from):
            return '550 Invalid sender address'
        return await super().handle_DATA(server, session, envelope)

    def is_valid_sender(self, sender):
        # Add logic to validate sender address
        return True  # Replace with actual validation logic

async def main():
    controller = Controller(CustomSMTP, port=1025)
    controller.start()
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())