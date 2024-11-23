def get_rss_feed(folder):
    if not user_has_permission(folder):
        # Vulnerability: Infinite loop if user does not have permission
        while True:
            pass  # This creates a denial of service
    return generate_rss_feed(folder)