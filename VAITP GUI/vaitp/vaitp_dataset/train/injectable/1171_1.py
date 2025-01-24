import asyncio
import re
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP

class CustomSMTP(SMTP):
    async def handle_DATA(self, server, session, envelope):
        # Implement strict validation for sender addresses
        if not self.is_valid_sender(envelope.mail_from):
            return '550 Invalid sender address'
        return await super().handle_DATA(server, session, envelope)

    def is_valid_sender(self, sender):
        # Add logic to validate sender address using a regex pattern
        if not sender:
          return False
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(pattern, sender):
          return True
        else:
          return False


async def main():
    controller = Controller(CustomSMTP(), hostname='0.0.0.0', port=1025)
    controller.start()
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())
