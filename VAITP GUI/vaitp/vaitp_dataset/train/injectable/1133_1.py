import asyncio
from aiosmtpd.controller import Controller

class CustomSMTPServer:
    async def handle_DATA(self, server, session, envelope):
        # Handle the email data here
        return '250 Message accepted for delivery'

async def main():
    controller = Controller(CustomSMTPServer(), hostname='localhost', port=8025)
    controller.start()

    # Simulate STARTTLS command handling
    # Ensure that no unencrypted commands are accepted after STARTTLS
    await asyncio.sleep(1)  # Simulate server running
    print("Server running...")

if __name__ == "__main__":
    asyncio.run(main())