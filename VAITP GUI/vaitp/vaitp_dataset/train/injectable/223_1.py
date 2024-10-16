from future.standard_library import install_aliases
install_aliases()

from urllib.parse import urlparse, urlunparse

def parse_cookie(cookie):
    cookie_parts = cookie.split(';')
    cookie_dict = {}
    for part in cookie_parts:
        try:
            key, value = part.strip().split('=', 1)  # Limit splits to 1 to avoid ValueError
            cookie_dict[key] = value
        except ValueError:
            # Handle cases where the cookie part is malformed
            print(f"Warning: Malformed cookie part: '{part}'")
            continue
    return cookie_dict

def set_cookie(cookie_dict):
    cookie_parts = []
    for key, value in cookie_dict.items():
        cookie_parts.append(f'{key}={value}')
    return '; '.join(cookie_parts)

def main():
    url = 'https://example.com'
    cookie = 'a=b; c=d; e=f'
    parsed_url = urlparse(url)
    parsed_url = parsed_url._replace(netloc='example.com:8080')
    new_url = urlunparse(parsed_url)
    
    # Validate and parse the cookie
    cookie_dict = parse_cookie(cookie)
    new_cookie = set_cookie(cookie_dict)
    print(f'Setting cookie: {new_cookie}')

if __name__ == '__main__':
    main()