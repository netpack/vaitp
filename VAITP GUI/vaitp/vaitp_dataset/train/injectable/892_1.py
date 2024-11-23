def is_url_allowed(url):
    # Check against the URL preview blacklist
    if url in url_preview_url_blacklist:
        return False
    return True

def fetch_url_preview(url):
    if not is_url_allowed(url):
        raise ValueError("URL is blacklisted")

    # Fetch the URL and process the response
    response = requests.get(url)
    
    # Check for oEmbed or image URL response
    if is_oembed_url(url):
        if response.headers['Content-Type'] != 'application/json':
            raise ValueError("Non-JSON response for oEmbed URL")
        # Process oEmbed response
    elif is_image_url(url):
        if not is_image_response(response):
            raise ValueError("Non-image response for image URL")
        # Process image response
    else:
        raise ValueError("Unsupported URL type")

def is_oembed_url(url):
    # Logic to determine if URL is oEmbed
    pass

def is_image_url(url):
    # Logic to determine if URL is an image
    pass

def is_image_response(response):
    # Logic to check if the response is an image
    pass