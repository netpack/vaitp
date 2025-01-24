import requests
from urllib.parse import urlparse, urljoin

url_preview_url_blacklist = []  # Example blacklist, can be populated elsewhere
ALLOWED_SCHEMES = ['http', 'https']


def is_url_allowed(url):
    # Check against the URL preview blacklist
    if url in url_preview_url_blacklist:
        return False
    return True


def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme in ALLOWED_SCHEMES, result.netloc])
    except:
        return False


def fetch_url_preview(url):
    if not is_valid_url(url):
        raise ValueError("Invalid URL")
    if not is_url_allowed(url):
        raise ValueError("URL is blacklisted")


    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
    except requests.exceptions.RequestException as e:
        raise ValueError(f"Error fetching URL: {e}")

    content_type = response.headers.get('Content-Type', '').lower()

    if is_oembed_url(url):
        if 'application/json' not in content_type:
             raise ValueError("Non-JSON response for oEmbed URL")
        # Process oEmbed response
        print("Processing oEmbed Response")
    elif is_image_url(url):
        if not is_image_response(response):
            raise ValueError("Non-image response for image URL")
        # Process image response
        print("Processing Image Response")
    else:
        raise ValueError("Unsupported URL type")


def is_oembed_url(url):
    # Logic to determine if URL is oEmbed
    # Example logic for demonstration purposes:
    return "oembed" in url


def is_image_url(url):
    # Logic to determine if URL is an image
    # Example logic for demonstration purposes:
    return url.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp'))


def is_image_response(response):
    # Logic to check if the response is an image
    content_type = response.headers.get('Content-Type', '').lower()
    return content_type.startswith('image/')
