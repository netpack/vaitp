import asyncio
from aiosmtpd.smtp import SMTP

class VulnerableSMTPServer(SMTP):
    async def handle_command(self, command, *args):
        if command == 'STARTTLS':
            # Simulate STARTTLS command without proper handling
            await self.start_tls()
        else:
            # Accept unencrypted commands after STARTTLS
            await super().handle_command(command, *args)

async def main():
    server = VulnerableSMTPServer()
    await server.start('localhost', 8025)

if __name__ == "__main__":
    asyncio.run(main())