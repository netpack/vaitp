def get_rss_feed(folder, user):
    if not user.has_permission('View', folder):
        raise PermissionError("User  does not have permission to access this folder.")
    
    # Proceed with generating the RSS feed
    rss_feed = generate_rss_feed(folder)
    return rss_feed