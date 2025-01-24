import aiohttp
import asyncio
import certifi
import ssl

async def fetch(url):
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_context)) as session:
        try:
            async with session.get(url, timeout=10) as response:
                response.raise_for_status()
                return await response.text()
        except aiohttp.ClientError as e:
             print(f"Error fetching {url}: {e}")
             return None
        except asyncio.TimeoutError:
             print(f"Timeout Error fetching {url}")
             return None


async def main():
    url = 'https://example.com'  # Replace with the target URL, use https
    response = await fetch(url)
    if response:
        print(response)

if __name__ == '__main__':
    asyncio.run(main())
