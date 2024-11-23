def fetch_url_preview(url):
    # Assume url_preview_url_blacklist is not checked, leading to potential bypass
    response = requests.get(url)

    # Process the response without validating content type
    if is_oembed_url(url):
        # Directly process any response, including non-JSON
        process_oembed_response(response)
    elif is_image_url(url):
        # Directly process any response, including non-image
        process_image_response(response)
    else:
        raise ValueError("Unsupported URL type")

def is_oembed_url(url):
    # Logic to determine if URL is oEmbed
    return url.endswith('.json')

def is_image_url(url):
    # Logic to determine if URL is an image
    return url.lower().endswith(('.png', '.jpg', '.jpeg', '.gif'))

def process_oembed_response(response):
    # Process the oEmbed response without validation
    pass

def process_image_response(response):
    # Process the image response without validation
    pass